"""
multistage_correlator.py
------------------------
Block 3 — Multistage Correlator.

Receives incident_candidates from Block 2 (RiskAccumulator) and correlates
them into attack_narrative objects — each representing one coordinated campaign.

Three phases:
  Phase 1 — Graph construction
    Each incident_candidate becomes a node. Edges created when linking
    evidence exists. Four edge types (additive, capped at 1.0):
      shared_attacker_ip   0.90  — same external source IP in both nodes
      shared_asset         0.85  — same sensitive asset (via MITRE technique match)
      sequential_kill_chain 0.70 — stages progress forward, timestamps ordered
      stage_overlap        0.40  — same stage, both within correlation window
      temporal_proximity   0.25  — overlapping windows + same peer group (reinforce only)
    Minimum combined edge weight to connect: 0.50

  Phase 2 — Clustering
    Union-find on edges >= MIN_EDGE_WEIGHT → connected components.
    Quality filter removes noise clusters (UEBA login_hour accumulation).
    Minimum quality:
      2+ entities, OR
      1 entity with 3+ distinct stages, OR
      1 entity with known-bad external IP edge, OR
      1 entity with signature_rules hit confidence >= 0.80

  Phase 3 — Narrative assembly
    Entry point: lowest kill chain stage → earliest first_seen → highest score
    Confidence: 0.35×edge + 0.25×stage_coverage + 0.20×entity_factor + 0.20×severity
    Pre-assembles narrative_summary for LLM to refine, not construct from scratch.
"""
from __future__ import annotations

import os
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

# assign_peer_group lives in the UEBA module (Module 6), which may not be ported
# yet. Degrade gracefully: peer group is used ONLY by the temporal_proximity
# edge, which is reinforcement-only (it adds 0.25 < MIN_EDGE_WEIGHT and never
# creates a connection on its own). The fallback returns a UNIQUE group per
# entity so distinct entities never "share" a peer group — i.e. the reinforcement
# simply doesn't fire until real peer grouping lands, rather than mis-firing.
try:
    from ..ueba.ueba_profiler import assign_peer_group
except Exception:
    def assign_peer_group(entity_key: str) -> str:
        return f"__solo__:{entity_key}"


# =============================================================================
#  Configuration
# =============================================================================

# Edge type weights
W_SHARED_IP         = 0.90
W_SHARED_ASSET      = 0.85
W_SEQUENTIAL_STAGE  = 0.70
W_STAGE_OVERLAP     = 0.40
W_TEMPORAL_PROX     = 0.25

# Minimum combined edge weight to create a graph connection
MIN_EDGE_WEIGHT = 0.50

# Maximum time gap between two candidates to be considered same campaign
CORRELATION_WINDOW_HOURS = 4

# Maximum campaign duration
MAX_CAMPAIGN_DURATION_HOURS = 24

# Minimum campaign confidence to route to LLM
MIN_LLM_CONFIDENCE = 0.70

# RFC 1918 prefixes — used to distinguish external from internal IPs
_PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168.", "127.", "0.")

# MITRE techniques whose co-occurrence implies shared sensitive asset
# (two entities both showing this technique likely touched the same asset type)
_ASSET_TECHNIQUES: Dict[str, str] = {
    "T1213":     "phi_database",
    "T1021":     "phi_database",
    "T1530":     "s3_phi_bucket",
    "T1562":     "audit_logs",
    "T1552":     "hsm_keystore",
    "T1078.003": "privileged_accounts",
}

# High-confidence C2 rule names — only these trigger the same-indicator C2 constraint
_C2_RULE_NAMES = {"c2_dns_beacon"}

# Stage names for narrative assembly
_STAGE_NAMES: Dict[int, str] = {
    1: "Reconnaissance",      2: "Resource Development",
    3: "Initial Access",      4: "Execution",
    5: "Persistence",         6: "Privilege Escalation",
    7: "Defense Evasion",     8: "Credential Access",
    9: "Discovery",           10: "Lateral Movement",
    11: "Collection",         12: "Command and Control",
    13: "Exfiltration",       14: "Impact",
}

_SEVERITY_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


# =============================================================================
#  Data structures
# =============================================================================

@dataclass
class CandidateNode:
    """Enriched wrapper around an incident_candidate from Block 2."""
    entity_key:         str
    entity_type:        str
    severity:           str
    short_score:        float
    long_score:         float
    stages:             Set[int]             # all stages across both windows
    first_seen:         datetime
    last_seen:          datetime
    external_ips:       Set[str]             # non-RFC1918 source IPs
    mitre_techniques:   Set[str]             # all technique IDs in top_risk_events
    asset_types:        Set[str]             # inferred from techniques
    c2_indicators:      Set[str]             # source IPs of confirmed C2 rule hits
    peer_group:         str
    rule_max_confidence: float               # highest rule confidence in top_risk_events
    top_risk_events:    List[dict]
    raw_ic:             dict                 # original incident_candidate


@dataclass
class Campaign:
    """A correlated cluster of CandidateNodes forming one attack campaign."""
    campaign_id:        str
    nodes:              List[CandidateNode]
    edges:              Dict[Tuple[str, str], float]   # (key_a, key_b) → weight
    max_edge_weight:    float
    stages:             Set[int]
    external_ips:       Set[str]
    confidence:         float


# =============================================================================
#  Union-Find
# =============================================================================

class _UnionFind:
    def __init__(self, keys: List[str]):
        self._parent = {k: k for k in keys}
        self._rank   = {k: 0 for k in keys}

    def find(self, x: str) -> str:
        while self._parent[x] != x:
            self._parent[x] = self._parent[self._parent[x]]
            x = self._parent[x]
        return x

    def union(self, a: str, b: str):
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self._rank[ra] < self._rank[rb]:
            ra, rb = rb, ra
        self._parent[rb] = ra
        if self._rank[ra] == self._rank[rb]:
            self._rank[ra] += 1

    def groups(self) -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = defaultdict(list)
        for k in self._parent:
            result[self.find(k)].append(k)
        return dict(result)


# =============================================================================
#  Helpers
# =============================================================================

def _is_external(ip: str) -> bool:
    if not ip or not isinstance(ip, str):
        return False
    return not any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def _parse_ts(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        dt = datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _within_correlation_window(a: CandidateNode, b: CandidateNode) -> bool:
    """True if both candidates overlap in time within CORRELATION_WINDOW_HOURS."""
    gap = abs((a.first_seen - b.first_seen).total_seconds()) / 3600
    return gap <= CORRELATION_WINDOW_HOURS


def _stages_progress(a: CandidateNode, b: CandidateNode) -> bool:
    """
    True if b's stages are a forward progression from a's stages.
    b must have at least one stage strictly higher than any of a's stages,
    and b's first_seen must be after a's first_seen.
    """
    if b.first_seen <= a.first_seen:
        return False
    return max(b.stages, default=0) > max(a.stages, default=0)


def _build_node(ic: dict) -> CandidateNode:
    """Extract all attributes needed for correlation from one incident_candidate."""
    stages = set(
        ic.get("short_window", {}).get("stages_covered", []) +
        ic.get("long_window",  {}).get("stages_covered", [])
    )
    stages.discard(0)

    external_ips:    Set[str] = set()
    mitre_techniques: Set[str] = set()
    asset_types:     Set[str] = set()
    c2_indicators:   Set[str] = set()
    rule_max_conf = 0.0

    for re in ic.get("top_risk_events", []):
        src_ip = re.get("source_ip", "")
        if _is_external(src_ip):
            external_ips.add(src_ip)

        tid = re.get("mitre_technique_id", "")
        if tid:
            mitre_techniques.add(tid)
            asset = _ASSET_TECHNIQUES.get(tid)
            if asset:
                asset_types.add(asset)

        # Track high-confidence C2 rule hits (rule-based, not ML-inferred)
        if re.get("detector") == "signature_rules":
            for rname in re.get("triggered_rules", []):
                if rname in _C2_RULE_NAMES and src_ip:
                    c2_indicators.add(src_ip)  # same source host = same C2 session
            rule_max_conf = max(rule_max_conf, float(re.get("confidence", 0)))

    first_seen = _parse_ts(ic.get("first_seen", "")) or datetime.now(timezone.utc)
    last_seen  = _parse_ts(ic.get("last_seen",  "")) or first_seen

    return CandidateNode(
        entity_key       = ic["entity_key"],
        entity_type      = ic["entity_type"],
        severity         = ic["severity"],
        short_score      = ic.get("short_window", {}).get("score", 0.0),
        long_score       = ic.get("long_window",  {}).get("score", 0.0),
        stages           = stages,
        first_seen       = first_seen,
        last_seen        = last_seen,
        external_ips     = external_ips,
        mitre_techniques = mitre_techniques,
        asset_types      = asset_types,
        c2_indicators    = c2_indicators,
        peer_group       = assign_peer_group(ic["entity_key"]),
        rule_max_confidence = rule_max_conf,
        top_risk_events  = ic.get("top_risk_events", []),
        raw_ic           = ic,
    )


# =============================================================================
#  Edge computation
# =============================================================================

def _compute_edge(a: CandidateNode, b: CandidateNode) -> float:
    """
    Compute the combined edge weight between two candidate nodes.
    Returns 0.0 if below MIN_EDGE_WEIGHT (no connection).
    All applicable edge weights are summed then capped at 1.0.
    """
    weight = 0.0

    # ── Shared attacker IP (0.90) ─────────────────────────────────────
    shared_ips = a.external_ips & b.external_ips
    if shared_ips:
        weight += W_SHARED_IP

    # ── Shared asset (0.85) ──────────────────────────────────────────
    # Same MITRE technique implying same sensitive asset type.
    # C2 (T1071.004) only counts if same actual C2 indicator (source host).
    shared_assets = a.asset_types & b.asset_types
    if shared_assets:
        weight += W_SHARED_ASSET
    # Strict C2 same-indicator: T1071/T1071.004 only if same source host
    c2_tech_a = {"T1071", "T1071.004"} & a.mitre_techniques
    c2_tech_b = {"T1071", "T1071.004"} & b.mitre_techniques
    if c2_tech_a and c2_tech_b:
        shared_c2 = a.c2_indicators & b.c2_indicators
        if shared_c2:
            weight += W_SHARED_ASSET   # same C2 session = strong asset link
        # else: no C2 link even if both have C2 stage (different infrastructure)

    # ── Sequential kill chain (0.70) ─────────────────────────────────
    if _within_correlation_window(a, b):
        if _stages_progress(a, b):
            weight += W_SEQUENTIAL_STAGE
        elif _stages_progress(b, a):
            weight += W_SEQUENTIAL_STAGE

    # ── Stage overlap (0.40) ─────────────────────────────────────────
    shared_stages = a.stages & b.stages
    # Exclude stage 7 (Defense Evasion) from overlap — it's almost universal
    # due to UEBA login_hour fallback and adds no discrimination
    meaningful_overlap = shared_stages - {7}
    if meaningful_overlap and _within_correlation_window(a, b):
        weight += W_STAGE_OVERLAP

    # ── Temporal proximity (0.25) — reinforcement only ───────────────
    # Only adds weight when at least one stronger edge already exists.
    # Never sole reason for a connection (0.25 < MIN_EDGE_WEIGHT 0.50).
    if weight > 0 and a.peer_group == b.peer_group:
        if _within_correlation_window(a, b):
            weight += W_TEMPORAL_PROX

    return min(weight, 1.0)


# =============================================================================
#  Quality filter
# =============================================================================

def _cluster_passes_quality(
    nodes: List[CandidateNode],
    edges: Dict[Tuple[str, str], float],
) -> bool:
    """
    True if the cluster meets minimum quality to become an attack narrative.
    Filters out UEBA login_hour accumulation noise and ML-only false positives.
    """
    if len(nodes) >= 2:
        return True

    # Single-entity cluster: must have a confirmed signature_rules hit first.
    # UEBA + ML alone is not sufficient — too many false positives from
    # behavioral baseline deviations that aren't confirmed attacks.
    n = nodes[0]
    has_rule_hit = n.rule_max_confidence >= 0.80
    if not has_rule_hit:
        return False

    if len(n.stages - {7}) >= 2:     # 2+ distinct meaningful stages
        return True
    if n.external_ips:                # known external IP link
        return True
    if n.rule_max_confidence >= 0.90: # very high confidence rule hit alone
        return True

    return False


# =============================================================================
#  Confidence formula
# =============================================================================

def _compute_confidence(
    nodes:          List[CandidateNode],
    max_edge:       float,
    all_stages:     Set[int],
) -> float:
    """
    Cluster confidence: weighted combination of edge quality, stage coverage,
    entity count, and entity severity.
    """
    edge_quality   = max_edge
    stage_coverage = len(all_stages) / 14.0
    entity_factor  = min(1.0, len(nodes) / 5.0)
    sev_scores     = [_SEVERITY_ORDER.get(n.severity, 0) / 4.0 for n in nodes]
    severity_factor = sum(sev_scores) / max(len(sev_scores), 1)

    return round(
        0.35 * edge_quality
        + 0.25 * stage_coverage
        + 0.20 * entity_factor
        + 0.20 * severity_factor,
        4
    )


# =============================================================================
#  Narrative assembly
# =============================================================================

def _entry_point(nodes: List[CandidateNode]) -> CandidateNode:
    """
    Identify attack entry point.
    Priority: lowest kill chain stage → earliest first_seen → highest score.
    """
    def sort_key(n: CandidateNode):
        min_stage = min(n.stages, default=99)
        score     = -(n.short_score + n.long_score)
        return (min_stage, n.first_seen.timestamp(), score)
    return sorted(nodes, key=sort_key)[0]


def _build_attack_stages(nodes: List[CandidateNode]) -> List[dict]:
    """
    Build ordered attack_stages array. Each stage groups entities and evidence.
    Stage 7 is included only when it has corroborating rule evidence (not UEBA alone).
    """
    stage_entities: Dict[int, List[dict]] = defaultdict(list)
    stage_techniques: Dict[int, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    stage_evidence: Dict[int, Set[str]] = defaultdict(set)
    stage_first_seen: Dict[int, datetime] = {}

    for node in nodes:
        for re in node.top_risk_events:
            stage = int(re.get("kill_chain_stage", 0))
            if not stage:
                continue

            # For stage 7, only count if it comes from a rule hit, not UEBA temporal
            if stage == 7 and re.get("detector") == "ueba":
                driver = re.get("ueba_details", {}).get("anomaly_driver", "")
                if driver in ("login_hour", "login_day_of_week", "has_source_ip"):
                    continue

            tid = re.get("mitre_technique_id", "")
            if tid:
                stage_techniques[stage][tid] += 1

            for rname in re.get("triggered_rules", []):
                stage_evidence[stage].add(rname)

            ts_str = re.get("timestamp", "")
            ts = _parse_ts(ts_str)
            if ts and (stage not in stage_first_seen or ts < stage_first_seen[stage]):
                stage_first_seen[stage] = ts

            if node.entity_key not in {e["entity"] for e in stage_entities[stage]}:
                stage_entities[stage].append({
                    "entity":   node.entity_key,
                    "type":     node.entity_type,
                    "severity": node.severity,
                })

    stages_present = (
        set(stage_entities.keys())
        | set(s for node in nodes for s in node.stages)
    )
    stages_present.discard(0)

    result = []
    for stage in sorted(stages_present):
        # Primary technique = most-seen technique at this stage
        tech_counts = stage_techniques.get(stage, {})
        primary_tech = max(tech_counts, key=tech_counts.get) if tech_counts else ""
        first_ts = stage_first_seen.get(stage)

        result.append({
            "stage":         stage,
            "name":          _STAGE_NAMES.get(stage, f"Stage {stage}"),
            "technique":     primary_tech,
            "entities":      stage_entities.get(stage, []),
            "entity_count":  len(stage_entities.get(stage, [])),
            "first_seen":    first_ts.isoformat() if first_ts else "",
            "evidence":      sorted(stage_evidence.get(stage, set())),
        })

    return result


def _extract_iocs(nodes: List[CandidateNode]) -> dict:
    """Collect all IOCs from a campaign cluster."""
    external_ips:    Set[str] = set()
    techniques:      Set[str] = set()
    asset_types:     Set[str] = set()
    affected_users:  Set[str] = set()
    affected_hosts:  Set[str] = set()

    for node in nodes:
        external_ips.update(node.external_ips)
        techniques.update(node.mitre_techniques)
        asset_types.update(node.asset_types)

        if node.entity_type == "user":
            affected_users.add(node.entity_key)
        elif node.entity_type in ("ip", "host"):
            affected_hosts.add(node.entity_key)

    return {
        "external_ips":      sorted(external_ips),
        "mitre_techniques":  sorted(techniques),
        "affected_assets":   sorted(asset_types),
        "affected_users":    sorted(affected_users),
        "affected_hosts":    sorted(affected_hosts),
    }


def _build_narrative_summary(
    entry:          CandidateNode,
    nodes:          List[CandidateNode],
    attack_stages:  List[dict],
    iocs:           dict,
    duration_min:   int,
    campaign_id:    str,
) -> str:
    """
    Pre-assemble a factual narrative summary for LLM refinement.
    Contains only verifiable data — no inference. LLM adds reasoning.
    """
    lines = []

    # Opening: when and entry point
    ts = entry.first_seen.strftime("%Y-%m-%d %H:%M UTC")
    lines.append(
        f"Attack campaign {campaign_id} began at {ts} with entity "
        f"'{entry.entity_key}' (type: {entry.entity_type}) "
        f"as the likely entry point."
    )

    # Initial access stage
    s3 = next((s for s in attack_stages if s["stage"] == 3), None)
    if s3 and s3["evidence"]:
        entities_str = ", ".join(e["entity"] for e in s3["entities"][:3])
        lines.append(
            f"Initial Access (Stage 3) was detected via {', '.join(s3['evidence'][:2])} "
            f"affecting {entities_str}."
        )

    # External attacker IPs
    if iocs["external_ips"]:
        lines.append(
            f"Attacker infrastructure identified: {', '.join(iocs['external_ips'][:4])}."
        )

    # Credential access
    s8 = next((s for s in attack_stages if s["stage"] == 8), None)
    if s8:
        lines.append(
            f"Credential Access (Stage 8) involved "
            f"{s8['entity_count']} entities with techniques: {', '.join(s8['evidence'][:3])}."
        )

    # Lateral movement
    s10 = next((s for s in attack_stages if s["stage"] == 10), None)
    if s10:
        lm_entities = ", ".join(e["entity"] for e in s10["entities"][:3])
        lines.append(
            f"Lateral Movement (Stage 10) detected: {lm_entities} accessed "
            f"sensitive assets without authorisation."
        )

    # Collection
    s11 = next((s for s in attack_stages if s["stage"] == 11), None)
    if s11:
        lines.append(
            f"Data Collection (Stage 11): {s11['entity_count']} entities accessed "
            f"sensitive repositories ({', '.join(iocs['affected_assets'])})."
        )

    # C2
    s12 = next((s for s in attack_stages if s["stage"] == 12), None)
    if s12 and s12["evidence"]:
        lines.append(
            f"Command and Control (Stage 12) activity detected: {', '.join(s12['evidence'][:2])}."
        )

    # Exfiltration
    s13 = next((s for s in attack_stages if s["stage"] == 13), None)
    if s13:
        lines.append(f"Exfiltration indicators (Stage 13) detected.")

    # Closing: scale
    lines.append(
        f"Campaign duration: {duration_min} minutes. "
        f"{len(nodes)} entities affected. "
        f"{len(attack_stages)} of 14 kill chain stages covered. "
        f"MITRE techniques: {', '.join(iocs['mitre_techniques'][:6])}."
    )

    return " ".join(lines)


def _build_llm_context(
    narrative_summary: str,
    attack_narrative:  dict,
) -> dict:
    """Build the llm_context payload for AI agent routing."""
    severity = attack_narrative["severity"]
    entry    = attack_narrative["entry_point"]
    n_ent    = attack_narrative["entity_count"]
    n_stages = len(attack_narrative["kill_chain_coverage"])
    duration = attack_narrative["duration_minutes"]

    system_prompt = (
        f"You are a senior threat analyst reviewing a confirmed {severity} security incident. "
        f"A multi-stage attack campaign has been automatically detected and correlated across "
        f"{n_ent} entities over {duration} minutes, covering {n_stages} MITRE ATT&CK kill chain stages. "
        f"You will receive structured detection data and a factual summary. "
        f"Your tasks depend on the agent role assigned. "
        f"Do not fabricate details not present in the structured data. "
        f"Use precise security terminology. Be concise and actionable."
    )

    # Determine which agents should receive this campaign
    agent_targets = ["risk_scorer", "report_generator"]
    if _SEVERITY_ORDER.get(severity, 0) >= _SEVERITY_ORDER["HIGH"]:
        agent_targets.append("remediation")
    if n_stages >= 4:
        agent_targets.append("anomaly_explainer")
    if _SEVERITY_ORDER.get(severity, 0) >= _SEVERITY_ORDER["CRITICAL"]:
        agent_targets.append("investigator")

    return {
        "system_prompt":    system_prompt,
        "narrative_summary": narrative_summary,
        "structured_data":  {
            "campaign_id":        attack_narrative["campaign_id"],
            "severity":           severity,
            "confidence":         attack_narrative["confidence"],
            "duration_minutes":   duration,
            "entry_point":        entry,
            "attack_timeline":    attack_narrative["attack_stages"],
            "iocs":               attack_narrative["iocs"],
            "affected_entities":  [
                {
                    "entity":   n["entity_key"],
                    "type":     n["entity_type"],
                    "severity": n["severity"],
                    "stages":   list(n["stages"]),
                }
                for n in attack_narrative.get("_nodes_raw", [])
            ],
            "top_evidence":       sorted(
                [
                    re for n in attack_narrative.get("_nodes_raw", [])
                    for re in n["top_risk_events"]
                ],
                key=lambda r: float(r.get("score", 0)),
                reverse=True,
            )[:10],
        },
        "agent_targets":    agent_targets,
    }


# =============================================================================
#  MultistageCorrelator
# =============================================================================

class MultistageCorrelator:
    """
    Correlates incident_candidates from Block 2 into attack_narrative objects.

    Usage:
        correlator = MultistageCorrelator()
        narratives, noise = correlator.correlate(incident_candidates)
        correlator.save_graph("results/block3_graph.json")
        correlator.save_narratives(narratives, "results/attack_narratives.json")
        for n in narratives:
            if n["confidence"] >= MIN_LLM_CONFIDENCE:
                route_to_llm(n["llm_context"])
    """

    def __init__(self):
        # Preserved after each correlate() call — available for inspection / saving
        self._last_nodes:     List[CandidateNode]              = []
        self._last_edges:     Dict[Tuple[str,str], float]      = {}
        self._last_campaigns: List[Campaign]                   = []
        self._last_noise:     List[CandidateNode]              = []

    # ------------------------------------------------------------------ #
    # Public entry point
    # ------------------------------------------------------------------ #

    def correlate(
        self,
        incident_candidates: List[dict],
    ) -> Tuple[List[dict], List[dict]]:
        """
        Full three-phase correlation pipeline.

        Args:
            incident_candidates: list of incident_candidate dicts from Block 2.
                                  Caller should deduplicate by entity_key (keep highest severity).

        Returns:
            (attack_narratives, noise_candidates)
            attack_narratives: List[dict] — correlated campaigns, sorted by severity desc
            noise_candidates:  List[dict] — filtered-out single-entity low-confidence clusters
        """
        if not incident_candidates:
            return [], []

        # Deduplicate by entity_key — keep highest severity
        deduped = self._deduplicate(incident_candidates)
        print(f"[Correlator] {len(deduped)} unique entities after dedup "
              f"(from {len(incident_candidates)} candidates)")

        # Phase 1 — build nodes and edges
        nodes = [_build_node(ic) for ic in deduped]
        node_map: Dict[str, CandidateNode] = {n.entity_key: n for n in nodes}
        edges   = self._build_edges(nodes)
        print(f"[Correlator] {len(edges)} edges above threshold {MIN_EDGE_WEIGHT}")

        # Phase 2 — cluster
        clusters, noise = self._cluster(nodes, node_map, edges)
        print(f"[Correlator] {len(clusters)} quality clusters, "
              f"{len(noise)} noise candidates filtered")

        # Phase 3 — assemble narratives
        narratives = [self._build_narrative(c) for c in clusters]

        # Sort by severity then confidence
        narratives.sort(
            key=lambda n: (
                _SEVERITY_ORDER.get(n["severity"], 0),
                n["confidence"]
            ),
            reverse=True,
        )

        # Preserve graph state for save_graph() / inspection
        self._last_nodes     = nodes
        self._last_edges     = edges
        self._last_campaigns = clusters
        self._last_noise     = noise

        noise_list = [n.raw_ic for n in noise]
        return narratives, noise_list

    # ------------------------------------------------------------------ #
    # Persistence
    # ------------------------------------------------------------------ #

    def save_graph(self, path: str) -> None:
        """
        Persist the graph from the last correlate() call to JSON.

        Graph structure:
          nodes   — each entity with attributes used during correlation
          edges   — pairs with combined weight + contributing edge types
          campaigns — cluster membership + quality metrics
          noise   — filtered-out candidates

        Useful for debugging, visualization (load into Gephi/NetworkX),
        and auditing why two entities were or were not connected.
        """
        import json as _json
        from datetime import datetime as _dt

        def _ser(obj):
            if isinstance(obj, (_dt,)):
                return obj.isoformat()
            if isinstance(obj, set):
                return sorted(obj)
            raise TypeError(f"Not serializable: {type(obj)}")

        nodes_out = []
        for n in self._last_nodes:
            nodes_out.append({
                "entity_key":          n.entity_key,
                "entity_type":         n.entity_type,
                "severity":            n.severity,
                "short_score":         n.short_score,
                "long_score":          n.long_score,
                "stages":              sorted(n.stages),
                "first_seen":          n.first_seen.isoformat(),
                "last_seen":           n.last_seen.isoformat(),
                "external_ips":        sorted(n.external_ips),
                "mitre_techniques":    sorted(n.mitre_techniques),
                "asset_types":         sorted(n.asset_types),
                "c2_indicators":       sorted(n.c2_indicators),
                "peer_group":          n.peer_group,
                "rule_max_confidence": n.rule_max_confidence,
            })

        # Reconstruct edge types for each edge (for auditability)
        edges_out = []
        for (src, tgt), weight in sorted(
            self._last_edges.items(), key=lambda x: -x[1]
        ):
            a = next((n for n in self._last_nodes if n.entity_key == src), None)
            b = next((n for n in self._last_nodes if n.entity_key == tgt), None)
            types = []
            if a and b:
                if a.external_ips & b.external_ips:
                    types.append("shared_attacker_ip")
                if a.asset_types & b.asset_types:
                    types.append("shared_asset")
                if _stages_progress(a, b) or _stages_progress(b, a):
                    types.append("sequential_kill_chain")
                meaningful = (a.stages & b.stages) - {7}
                if meaningful:
                    types.append("stage_overlap")
                if a.peer_group == b.peer_group:
                    types.append("temporal_proximity")
            edges_out.append({
                "source":      src,
                "target":      tgt,
                "weight":      round(weight, 4),
                "edge_types":  types,
            })

        campaigns_out = []
        for c in self._last_campaigns:
            campaigns_out.append({
                "campaign_id":    c.campaign_id,
                "entity_count":   len(c.nodes),
                "entities":       [n.entity_key for n in c.nodes],
                "stages":         sorted(c.stages),
                "external_ips":   sorted(c.external_ips),
                "confidence":     c.confidence,
                "max_edge_weight": c.max_edge_weight,
                "edge_count":     len(c.edges),
            })

        graph = {
            "metadata": {
                "generated_at":    _dt.now().isoformat(),
                "total_nodes":     len(self._last_nodes),
                "total_edges":     len(self._last_edges),
                "campaigns":       len(self._last_campaigns),
                "noise_filtered":  len(self._last_noise),
                "min_edge_weight": MIN_EDGE_WEIGHT,
            },
            "nodes":     nodes_out,
            "edges":     edges_out,
            "campaigns": campaigns_out,
            "noise":     [n.entity_key for n in self._last_noise],
        }

        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            _json.dump(graph, f, indent=2, default=_ser)
        print(f"[Correlator] Graph saved → {path}  "
              f"({len(nodes_out)} nodes, {len(edges_out)} edges)")

    @staticmethod
    def save_narratives(narratives: List[dict], path: str) -> None:
        """
        Persist attack_narratives to JSON.
        This is the handoff file Block 4 (DAL / PII scrub) reads from.
        """
        import json as _json

        # Make fully JSON-serializable (sets → lists, datetimes → str)
        def _clean(obj):
            if isinstance(obj, set):
                return sorted(obj)
            if hasattr(obj, "isoformat"):
                return obj.isoformat()
            return str(obj)

        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            _json.dump(narratives, f, indent=2, default=_clean)
        print(f"[Correlator] Narratives saved → {path}  ({len(narratives)} campaigns)")

    # ------------------------------------------------------------------ #
    # Phase 1 — Edge building
    # ------------------------------------------------------------------ #

    def _build_edges(
        self,
        nodes: List[CandidateNode],
    ) -> Dict[Tuple[str, str], float]:
        """O(n²) edge computation — fine for typical incident_candidate counts (<200)."""
        edges: Dict[Tuple[str, str], float] = {}
        for i, a in enumerate(nodes):
            for b in nodes[i + 1:]:
                w = _compute_edge(a, b)
                if w >= MIN_EDGE_WEIGHT:
                    key = (a.entity_key, b.entity_key)
                    edges[key] = w
        return edges

    # ------------------------------------------------------------------ #
    # Phase 2 — Clustering
    # ------------------------------------------------------------------ #

    def _cluster(
        self,
        nodes:    List[CandidateNode],
        node_map: Dict[str, CandidateNode],
        edges:    Dict[Tuple[str, str], float],
    ) -> Tuple[List[Campaign], List[CandidateNode]]:
        """Union-find clustering + quality filtering."""
        uf = _UnionFind([n.entity_key for n in nodes])
        for (a, b) in edges:
            uf.union(a, b)

        # Group nodes by component
        groups = uf.groups()
        campaigns: List[Campaign] = []
        noise:     List[CandidateNode] = []

        for root, member_keys in groups.items():
            cluster_nodes = [node_map[k] for k in member_keys if k in node_map]

            # Collect edges within this cluster
            cluster_edges = {
                (a, b): w for (a, b), w in edges.items()
                if a in member_keys and b in member_keys
            }
            max_edge = max(cluster_edges.values(), default=0.0)

            # Apply campaign duration cap — split clusters spanning > 24 hours
            sub_clusters = self._split_long_campaigns(cluster_nodes, cluster_edges)

            for sub_nodes, sub_edges, sub_max_edge in sub_clusters:
                if _cluster_passes_quality(sub_nodes, sub_edges):
                    all_stages = set().union(*(n.stages for n in sub_nodes))
                    all_stages.discard(0)
                    ext_ips    = set().union(*(n.external_ips for n in sub_nodes))
                    conf = _compute_confidence(sub_nodes, sub_max_edge, all_stages)
                    campaigns.append(Campaign(
                        campaign_id    = f"ATK-{len(campaigns)+1:04d}",
                        nodes          = sub_nodes,
                        edges          = sub_edges,
                        max_edge_weight= sub_max_edge,
                        stages         = all_stages,
                        external_ips   = ext_ips,
                        confidence     = conf,
                    ))
                else:
                    noise.extend(sub_nodes)

        return campaigns, noise

    def _split_long_campaigns(
        self,
        nodes: List[CandidateNode],
        edges: Dict[Tuple[str, str], float],
    ) -> List[Tuple[List[CandidateNode], Dict[Tuple[str,str],float], float]]:
        """
        If a cluster spans > MAX_CAMPAIGN_DURATION_HOURS, split by time bucket.
        Returns list of (nodes, edges, max_edge_weight) tuples.
        """
        if not nodes:
            return []

        first = min(n.first_seen for n in nodes)
        last  = max(n.last_seen  for n in nodes)
        span  = (last - first).total_seconds() / 3600

        if span <= MAX_CAMPAIGN_DURATION_HOURS:
            max_edge = max(edges.values(), default=0.0)
            return [(nodes, edges, max_edge)]

        # Split into MAX_CAMPAIGN_DURATION_HOURS buckets
        buckets: Dict[int, List[CandidateNode]] = defaultdict(list)
        for node in nodes:
            bucket = int((node.first_seen - first).total_seconds() / 3600
                         / MAX_CAMPAIGN_DURATION_HOURS)
            buckets[bucket].append(node)

        result = []
        for bucket_nodes in buckets.values():
            keys = {n.entity_key for n in bucket_nodes}
            bucket_edges = {(a,b):w for (a,b),w in edges.items()
                            if a in keys and b in keys}
            max_e = max(bucket_edges.values(), default=0.0)
            result.append((bucket_nodes, bucket_edges, max_e))
        return result

    # ------------------------------------------------------------------ #
    # Phase 3 — Narrative assembly
    # ------------------------------------------------------------------ #

    def _build_narrative(self, campaign: Campaign) -> dict:
        """Assemble a complete attack_narrative dict from a Campaign cluster."""
        nodes = sorted(
            campaign.nodes,
            key=lambda n: (min(n.stages, default=99), n.first_seen.timestamp())
        )

        entry        = _entry_point(nodes)
        attack_stages = _build_attack_stages(nodes)
        iocs         = _extract_iocs(nodes)

        # Anchor campaign first_seen to the earliest high-confidence attack stage.
        # Priority: S3 Initial Access → S10 Lateral Movement → S8 Credential Access
        # → S11 Collection → S13 Exfiltration → S9 Discovery.
        # Avoids S4/S12 which appear early from background endpoint/firewall traffic
        # and would distort the campaign start time.
        ANCHOR_STAGE_PRIORITY = [3, 10, 8, 11, 13, 9]
        attack_first = None
        stage_ts_map = {
            s["stage"]: _parse_ts(s["first_seen"])
            for s in attack_stages if s["first_seen"]
        }
        for anchor_stage in ANCHOR_STAGE_PRIORITY:
            ts = stage_ts_map.get(anchor_stage)
            if ts:
                attack_first = ts
                break
        first_seen = attack_first or min(n.first_seen for n in nodes)
        last_seen  = max(n.last_seen  for n in nodes)
        duration   = max(1, int((last_seen - first_seen).total_seconds() / 60))

        # Overall campaign severity = highest among all member entities
        severity = max(
            (n.severity for n in nodes),
            key=lambda s: _SEVERITY_ORDER.get(s, 0)
        )

        all_stages = sorted(campaign.stages)
        completeness = round(len(all_stages) / 14, 3)

        campaign_id = (
            f"ATK-{first_seen.strftime('%Y%m%d')}-"
            f"{first_seen.strftime('%H%M')}-"
            f"{campaign.campaign_id}"
        )

        narrative_summary = _build_narrative_summary(
            entry, nodes, attack_stages, iocs, duration, campaign_id
        )

        # Attach raw node data temporarily for llm_context builder
        narrative: dict = {
            "campaign_id":               campaign_id,
            "severity":                  severity,
            "confidence":                campaign.confidence,
            "first_seen":                first_seen.isoformat(),
            "last_seen":                 last_seen.isoformat(),
            "duration_minutes":          duration,
            "entry_point":               entry.entity_key,
            "entity_count":              len(nodes),
            "affected_entities":         [
                {
                    "entity_key":  n.entity_key,
                    "entity_type": n.entity_type,
                    "severity":    n.severity,
                    "stages":      sorted(n.stages),
                    "short_score": n.short_score,
                    "first_seen":  n.first_seen.isoformat(),
                    "last_seen":   n.last_seen.isoformat(),
                }
                for n in nodes
            ],
            "kill_chain_coverage":       all_stages,
            "kill_chain_completeness":   completeness,
            "attack_stages":             attack_stages,
            "iocs":                      iocs,
            "correlated_incident_ids":   [n.raw_ic.get("incident_id","") for n in nodes],
            "cluster_confidence":        campaign.confidence,
            "max_edge_weight":           campaign.max_edge_weight,
            "edge_count":                len(campaign.edges),
            "_nodes_raw":                [   # temp — used by llm_context builder, stripped after
                {"entity_key": n.entity_key, "entity_type": n.entity_type,
                 "severity": n.severity, "stages": sorted(n.stages),
                 "top_risk_events": n.top_risk_events}
                for n in nodes
            ],
        }

        narrative["llm_context"] = _build_llm_context(narrative_summary, narrative)
        del narrative["_nodes_raw"]   # clean up temp field

        return narrative

    # ------------------------------------------------------------------ #
    # Utilities
    # ------------------------------------------------------------------ #

    @staticmethod
    def _deduplicate(candidates: List[dict]) -> List[dict]:
        """
        Keep only the highest-severity incident_candidate per entity_key.
        Block 2 may emit multiple candidates per entity (HIGH then CRITICAL upgrade).
        Timestamps are reconciled: first_seen = min, last_seen = max across both.
        """
        import copy as _copy
        best: Dict[str, dict] = {}

        for ic in candidates:
            key = ic.get("entity_key", "")
            if not key:
                continue
            current = best.get(key)
            if current is None:
                best[key] = ic
            else:
                current_sev = _SEVERITY_ORDER.get(current["severity"], 0)
                new_sev     = _SEVERITY_ORDER.get(ic["severity"], 0)

                # Determine winner on severity then score
                if new_sev > current_sev:
                    winner, other = ic, current
                elif new_sev == current_sev:
                    cs = current.get("short_window", {}).get("score", 0)
                    ns = ic.get("short_window", {}).get("score", 0)
                    winner, other = (ic, current) if ns > cs else (current, ic)
                else:
                    winner, other = current, ic

                # Reconcile timestamps across both candidates
                merged = _copy.deepcopy(winner)
                w_first = winner.get("first_seen", "")
                o_first = other.get("first_seen",  "")
                w_last  = winner.get("last_seen",  "")
                o_last  = other.get("last_seen",   "")

                if w_first and o_first:
                    merged["first_seen"] = min(w_first, o_first)
                elif o_first:
                    merged["first_seen"] = o_first

                if w_last and o_last:
                    merged["last_seen"] = max(w_last, o_last)
                elif o_last:
                    merged["last_seen"] = o_last

                best[key] = merged

        return list(best.values())

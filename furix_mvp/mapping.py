"""CONTAINER C14 · DETERMINISTIC COMPLIANCE MAPPING — the code-first resolver.

This is the answer to "do compliance mapping with code, not an LLM."

For every event, control mapping is resolved by a fixed WATERFALL of
deterministic tiers. The LLM is NOT in this path. It is only reached as a
last-resort *suggestion* (handled in brain.py) when every tier below fails —
i.e. a genuinely novel event the rules and crosswalk have never seen.

    Tier 1  CROSSWALK TABLE      controls -> NIST/HIPAA via the SCF / NIST IR 8477
                                 lookup tables in compliance.py. Pure dictionary
                                 lookups. Authoritative for framework expansion.
    Tier 2  DETERMINISTIC RULES  keyword/signature regex (C6 `rule_controls`).
                                 "log contains CreateUser -> Control 5." if/then.
    Tier 3  EMBEDDING SIMILARITY SecureBERT vector match from RAG (ML, NOT an LLM,
                                 NOT generative). Used to corroborate / catch
                                 controls the keyword rules missed, gated by a
                                 cosine-similarity floor so weak matches are
                                 ignored.
    Tier 4  LLM FALLBACK         Gemma. NOT called here. brain.py calls it only
                                 when this resolver returns needs_llm=True, and
                                 even then the result is marked non-authoritative
                                 and needs_review.

Every tier is deterministic: the same finding always yields the same mapping.
That repeatability is exactly why auditors (and the client) trust code over an
LLM for the system of record.
"""
from __future__ import annotations

from . import config
from .compliance import (validate_controls, nist_for_controls,
                         hipaa_for_controls, CIS_CONTROLS)

# Tier labels surfaced in the response so the UI / audit log can show provenance.
TIER_CROSSWALK = "crosswalk_table"        # Tier 1
TIER_RULES = "deterministic_rules"        # Tier 2
TIER_EMBEDDING = "embedding_similarity"   # Tier 3  (ML, not LLM)
TIER_LLM = "llm_fallback"                 # Tier 4  (non-authoritative)


def _embedding_controls(ground: dict, floor: float) -> list[str]:
    """Controls from the RAG/embedding tier, accepted only above the floor.

    rag.retrieve() already applies its own RELEVANCE FLOOR and returns the
    surviving `controls`. We additionally keep only CIS control IDs (the graph /
    NIST subcats are expanded deterministically from those) and re-validate
    against the closed catalog. Non-generative, deterministic for a fixed index.
    """
    if not ground.get("available"):
        return []
    raw = [c for c in ground.get("controls", []) if str(c).startswith("Control")]
    return validate_controls(raw)


def resolve(finding: dict, ground: dict | None = None,
            *, embed_floor: float | None = None) -> dict:
    """Resolve a compliance mapping deterministically. No LLM is called here.

    Returns a dict:
      control_ids          authoritative CIS controls (validated, ordered)
      nist_subcategories   Tier-1 crosswalk expansion of control_ids
      hipaa_sections       Tier-1 crosswalk expansion (via NIST pivot)
      primary_tier         which tier produced the controls (or None)
      tiers_used           every tier that contributed
      provenance           {control_id: [tiers that found it]}
      confidence           0.0-1.0 deterministic confidence
      needs_llm            True only when NO deterministic tier could map it
      authoritative        True when the mapping stands on its own (no LLM needed)
      rationale            one-line human explanation
    """
    ground = ground or {}
    floor = config.MAPPING_EMBED_FLOOR if embed_floor is None else embed_floor

    # Tier 2 — deterministic keyword/signature rules (from C6).
    rule_controls = validate_controls(finding.get("rule_controls", []))

    # Tier 3 — embedding similarity (SecureBERT), corroborating / filling gaps.
    embed_controls = _embedding_controls(ground, floor)

    # Union with provenance, rules first (they are the most precise signal).
    provenance: dict[str, list[str]] = {}
    for c in rule_controls:
        provenance.setdefault(c, []).append(TIER_RULES)
    for c in embed_controls:
        tiers = provenance.setdefault(c, [])
        if TIER_EMBEDDING not in tiers:
            tiers.append(TIER_EMBEDDING)
    controls = list(provenance.keys())

    # Tier 1 — crosswalk table expansion (only meaningful if we have controls).
    nist = nist_for_controls(controls)
    hipaa = hipaa_for_controls(controls)

    # Confidence + which tier "won". Rules are exact pattern hits → highest.
    if rule_controls and embed_controls:
        confidence, primary = 0.95, TIER_RULES
    elif rule_controls:
        confidence, primary = 0.90, TIER_RULES
    elif embed_controls:
        confidence, primary = 0.70, TIER_EMBEDDING
    else:
        confidence, primary = 0.0, None

    needs_llm = not controls
    tiers_used = sorted({t for ts in provenance.values() for t in ts})
    if controls:
        tiers_used.append(TIER_CROSSWALK)

    return {
        "control_ids": controls,
        "nist_subcategories": nist,
        "hipaa_sections": hipaa,
        "primary_tier": primary,
        "tiers_used": tiers_used,
        "provenance": {c: provenance[c] for c in controls},
        "confidence": round(confidence, 2),
        "needs_llm": needs_llm,
        "authoritative": not needs_llm,
        "rationale": _rationale(rule_controls, embed_controls, controls),
    }


def merge_llm_suggestion(det: dict, llm_output: dict | None) -> dict:
    """Fold an LLM fallback suggestion into a deterministic-empty mapping.

    Called by brain.py ONLY for the unknown case (det['needs_llm'] is True).
    The LLM's control_ids are still validated against the closed catalog, then
    expanded through the SAME Tier-1 crosswalk so NIST/HIPAA stay deterministic.
    The result is flagged non-authoritative + needs_review: the LLM proposes,
    a human (or the crosswalk) disposes. The LLM is never the system of record.
    """
    if not det["needs_llm"]:
        return det                                   # deterministic mapping stands

    out = dict(det)
    if not llm_output:
        out.update(authoritative=False, needs_review=True,
                   rationale="No deterministic tier matched and LLM fallback "
                             "unavailable — flagged for human review.")
        return out

    suggested = validate_controls(llm_output.get("control_ids", []))
    out["control_ids"] = suggested
    out["nist_subcategories"] = nist_for_controls(suggested)   # Tier-1 crosswalk
    out["hipaa_sections"] = hipaa_for_controls(suggested)      # Tier-1 crosswalk
    out["primary_tier"] = TIER_LLM
    out["tiers_used"] = ([TIER_LLM] + ([TIER_CROSSWALK] if suggested else []))
    out["provenance"] = {c: [TIER_LLM] for c in suggested}
    out["confidence"] = 0.40                       # low: an unreviewed suggestion
    out["authoritative"] = False
    out["needs_review"] = True
    out["rationale"] = ("No deterministic tier matched; mapping is an LLM "
                        "SUGGESTION pending human review (non-authoritative).")
    return out


def _rationale(rule_controls: list[str], embed_controls: list[str],
               controls: list[str]) -> str:
    if not controls:
        return ("No deterministic rule or embedding match — event is novel; "
                "escalating to LLM fallback for a reviewable suggestion.")
    parts = []
    if rule_controls:
        named = ", ".join(CIS_CONTROLS.get(c, c) for c in rule_controls[:3])
        parts.append(f"keyword/signature rules matched {named}")
    if embed_controls:
        only_embed = [c for c in embed_controls if c not in rule_controls]
        if only_embed:
            parts.append(f"embedding similarity added {', '.join(only_embed[:3])}")
    parts.append("NIST/HIPAA expanded via the deterministic crosswalk table")
    return "; ".join(parts) + "."

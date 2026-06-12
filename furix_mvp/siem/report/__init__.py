"""Block 5 — LLM report generation against the in-house Gemma.

``LLMRouter.process_campaigns(scrubbed_narratives, *, mappings=...)`` sends each
scrubbed campaign narrative + its rule-hit evidence to Gemma (via furix's
``llm.complete_json``) and assembles the final analyst-facing incident report
(executive summary · attack timeline · risk assessment · remediation · key
evidence · anomaly explanation · detected anomalies · IOCs), re-identifying
placeholders on the way out.

Re-pointed from the source engine's OpenRouter client: no API key, no external
HTTP — model/endpoint/temperature come from furix config, ``MAX_TOKENS`` is
raised so reports don't truncate, and ``MOCK_LLM=1`` runs the wiring offline.
Pass the scrubber's in-memory ``mappings`` dict directly (the decoupled IPC).
"""
from .llm_router import LLMRouter, build_prompt_messages, MAX_TOKENS
from . import llm_router

__all__ = ["LLMRouter", "build_prompt_messages", "MAX_TOKENS", "llm_router"]

"""Block 4 — DAL: PII scrubbing before the LLM, re-identification after.

``DALScrubber.scrub(narratives)`` returns ``(scrubbed, mappings)`` IN MEMORY;
the report stage (Module 5) consumes that mappings dict directly. Disk
persistence (``save_mappings`` / ``load_mappings``) remains as a separate
local-audit helper — it is no longer the required scrubber→router IPC channel.

Identifiers are mapped to role-typed placeholders (EXEC_USER_1, ATTACKER_IP_2,
PHI_TABLE_1, …). Pure standard library; Presidio NER is an optional layer that
degrades to regex-only when not installed. Org-identifying classification
constants live in ``furix_mvp.siem.tenant``.
"""
from .dal_scrubber import DALScrubber
from . import dal_scrubber

__all__ = ["DALScrubber", "dal_scrubber"]

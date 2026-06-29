"""Pydantic request/response models for the AI Brain API."""
from __future__ import annotations
from typing import Any, Optional
from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    raw_log: str = Field(..., description="Raw security log/event text to analyze")
    log_type: str = Field("auto", description="Optional hint; 'auto' to let the model detect")
    agents: Optional[list[str]] = Field(None, description="Subset of agents; null = all enabled")
    force_llm: bool = Field(False, description="Full AI analysis: run ALL 5 agents through Gemma (override deterministic + narrative)")


class AgentResult(BaseModel):
    agent: str
    ok: bool
    output: dict[str, Any] = {}
    latency_ms: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    source: str = "llm"          # llm | mock | fallback | deterministic
    error: Optional[str] = None
    # Transparency: the exact prompt the model received (DAL-redacted) and its raw
    # response, so the UI can show clients precisely what went in and came out.
    prompt: Optional[str] = None
    raw: Optional[str] = None


class Verdict(BaseModel):
    severity: str
    risk_score: int
    confidence: float
    control_ids: list[str] = []
    nist_subcategories: list[str] = []
    hipaa_sections: list[str] = []
    is_anomaly: bool = False
    summary: str = ""


class AnalyzeResponse(BaseModel):
    finding_id: str
    log_type: str
    finding: dict[str, Any]
    verdict: Verdict
    agents: list[AgentResult]
    rag: dict[str, Any] = {}
    dal: dict[str, Any] = {}
    total_latency_ms: int = 0

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel


class Verdict(str, Enum):
    SAFE = "SAFE"
    LOW_RISK = "LOW_RISK"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class TriggeredSignal(BaseModel):
    id: str
    label: str
    weight: int


class ScoreBreakdown(BaseModel):
    sender_authenticity: int
    link_safety: int
    language_risk: int
    attachment_risk: int
    spoofing_risk: int


class VerdictResponse(BaseModel):
    verdict: Verdict
    score: int
    confidence: Confidence
    breakdown: ScoreBreakdown
    triggered_signals: list[TriggeredSignal]
    llm_reasoning: str
    recommended_action: str
    processing_ms: int


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
    retry_after: Optional[int] = None
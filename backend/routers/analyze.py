import time

from fastapi import APIRouter, Request

from limiter import limiter
from backend.models.request import EmailPayload
from backend.models.response import ScoreBreakdown, TriggeredSignal, VerdictResponse
from backend.services import aggregator as agg
from backend.services import llm_reasoning
from backend.services import normalizer
from backend.services import signals as signal_checks
from backend.services import threat_intel

router = APIRouter()


@router.post("/analyze", response_model=VerdictResponse)
@limiter.limit("30/minute")
async def analyze(request: Request, payload: EmailPayload) -> VerdictResponse:
    # Payload is extracted metadata only - never raw email body.
    start = time.monotonic()

    # Layer 1 - normalisation + prompt-injection gate
    sanitized, injection_signals = normalizer.sanitize(payload)
    _injection_detected = any(s.id == "PROMPT_INJECTION_ATTEMPT" for s in injection_signals)

    # Layer 2 - deterministic signal checks (on sanitised payload)
    layer2_signals = signal_checks.run_all(
        sanitized.sender,
        sanitized.auth,
        sanitized.urls,
        sanitized.attachments,
        sanitized.body_signals,
    )

    # Layer 3 - threat intel (parallel network checks; graceful on missing keys)
    threat_signals = await threat_intel.run_threat_intel(
        sanitized.urls, sanitized.sender.from_domain, sanitized.metadata.sender_ip
    )

    signals = injection_signals + layer2_signals + threat_signals

    # Layer 5 - weighted aggregation - score + per-category breakdown
    score, breakdown = agg.aggregate(signals)
    verdict, confidence = agg.score_to_verdict(score)

    # Layer 4 - LLM reasoning (skipped on injection or too few signals)
    if not _injection_detected and len(signals) >= llm_reasoning.LLM_SIGNAL_THRESHOLD:
        llm_text = await llm_reasoning.get_llm_reasoning(
            signals, sanitized.sender.from_domain, sanitized.subject,
            score, verdict.value,
        )
    elif _injection_detected:
        llm_text = "[Layer 4 skipped - prompt-injection attempt detected]"
    else:
        llm_text = "[Layer 4 skipped - insufficient signals for LLM enrichment]"

    # Rewrite alarming labels to benign equivalents for low-risk verdicts.
    display_signals = agg.apply_context_aware_labels(signals, verdict)

    return VerdictResponse(
        verdict=verdict,
        score=score,
        confidence=confidence,
        breakdown=ScoreBreakdown(**breakdown),
        triggered_signals=[
            TriggeredSignal(id=s.id, label=s.label, weight=s.weight)
            for s in display_signals
        ],
        llm_reasoning=llm_text,
        recommended_action=agg.recommended_action(verdict),
        processing_ms=int((time.monotonic() - start) * 1000),
    )
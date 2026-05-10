"""
score = clamp(sum(risk weights) − trust_discount, 0, 100)

Trust discounts: DKIM_PASS −15, SPF_PASS −10, DMARC_PASS −8.
Full-auth bonus (all three pass): −15 extra, total max −48.

Critical blows - instant 100: DOUBLE_EXT, PUNYCODE_DOMAIN (unconditional).
VIRUSTOTAL_HIT: critical blow unless full auth + count ≤ 5.

Thresholds: ≥60 MALICIOUS · ≥30 SUSPICIOUS · <30 SAFE
"""
from __future__ import annotations

import dataclasses

from services.signals import Signal
from models.response import Confidence, Verdict

# Unconditional critical blows - any one fires - instant score 100
_CRITICAL_BLOW_SIGNALS: frozenset[str] = frozenset({
    "DOUBLE_EXT",      # double extension (.pdf.exe) - deliberate evasion
    "PUNYCODE_DOMAIN",
})

# critical blow unless full auth + count ≤ threshold (see aggregate())
_VT_FULL_AUTH_THRESHOLD: int = 5


_TRUST_DISCOUNTS: dict[str, int] = {
    "DKIM_PASS":  15,
    "SPF_PASS":   10,
    "DMARC_PASS":  8,
}

_FULL_AUTH_IDS: frozenset[str] = frozenset({"SPF_PASS", "DKIM_PASS", "DMARC_PASS"})
_FULL_AUTH_BONUS_DISCOUNT: int = 15  # extra discount when all three auth checks pass


WEIGHTS: dict[str, float] = {
    "sender_authenticity": 0.25,
    "link_safety":         0.25,
    "language_risk":       0.20,
    "attachment_risk":     0.20,
    "spoofing_risk":       0.10,
}

# Category map - used for the per-category breakdown only (not for scoring).
# Every signal id must map to exactly one category.

SIGNAL_TO_CATEGORY: dict[str, str] = {
    "SPF_FAIL":                 "sender_authenticity",
    "DKIM_FAIL":                "sender_authenticity",
    "DMARC_FAIL":               "sender_authenticity",
    "REPLY_MISMATCH":           "sender_authenticity",
    "DISPLAY_SPOOF":            "sender_authenticity",
    "TRACKING_PIXEL":           "sender_authenticity",
    "GEOLOCATION_RISK":         "sender_authenticity",
    "IP_URL":                   "link_safety",
    "LINK_MISMATCH":            "link_safety",
    "SAFE_BROWSING":            "link_safety",
    "URL_SHORTENER":            "link_safety",
    "VIRUSTOTAL_HIT":           "link_safety",
    "PUNYCODE_DOMAIN":          "link_safety",
    "URL_COMPLEXITY_RISK":      "link_safety",
    "URGENCY_HIGH":             "language_risk",
    "CRED_REQUEST":             "language_risk",
    "FINANCIAL_MANIP":          "language_risk",
    "INVISIBLE_TEXT":           "language_risk",
    "GENERIC_GREETING":         "language_risk",
    "FAKE_SECURITY_ALERT":      "language_risk",
    "OTP_REQUEST":              "language_risk",
    "SPELLING_ERRORS":          "language_risk",
    "DOUBLE_EXT":               "attachment_risk",
    "MACRO_ENABLED":            "attachment_risk",
    "EXEC_MIME":                "attachment_risk",
    "HOMOGLYPH":                "spoofing_risk",
    "DOMAIN_NEW":               "spoofing_risk",
    "SUSPICIOUS_TLD":           "spoofing_risk",
    "PROMPT_INJECTION_ATTEMPT": "sender_authenticity",
}


_BREAKDOWN_CATEGORIES = list(SIGNAL_TO_CATEGORY.values())


def aggregate(signals: list[Signal]) -> tuple[int, dict[str, int]]:
    """
    Unconditional critical blows (DOUBLE_EXT, PUNYCODE_DOMAIN) return 100 immediately.
    VIRUSTOTAL_HIT is a critical blow unless full auth is present and count ≤ threshold.
    Otherwise: final = clamp(sum(risk weights) − trust_discount, 0, 100).
    """
    _critical_blow_breakdown = {cat: 100 for cat in set(SIGNAL_TO_CATEGORY.values())}

    for sig in signals:
        if sig.id in _CRITICAL_BLOW_SIGNALS:
            return 100, _critical_blow_breakdown

    signal_ids   = {s.id for s in signals}
    has_full_auth = _FULL_AUTH_IDS.issubset(signal_ids)

    for sig in signals:
        if sig.id == "VIRUSTOTAL_HIT":
            if not has_full_auth or sig.count > _VT_FULL_AUTH_THRESHOLD:
                return 100, _critical_blow_breakdown

    trust_discount = sum(_TRUST_DISCOUNTS.get(s.id, 0) for s in signals)
    if has_full_auth:
        trust_discount += _FULL_AUTH_BONUS_DISCOUNT

    risk_signals = [s for s in signals if s.id in SIGNAL_TO_CATEGORY]

    raw_sum = sum(s.weight for s in risk_signals)

    final = max(0, min(100, raw_sum - trust_discount))

    cat_points: dict[str, int] = {cat: 0 for cat in set(SIGNAL_TO_CATEGORY.values())}
    for sig in risk_signals:
        cat = SIGNAL_TO_CATEGORY.get(sig.id)
        if cat:
            cat_points[cat] += sig.weight
    breakdown = {cat: min(cat_points[cat], 100) for cat in cat_points}

    return final, breakdown


def score_to_verdict(score: int) -> tuple[Verdict, Confidence]:
    if score >= 60:
        return Verdict.MALICIOUS,  Confidence.HIGH
    if score >= 30:
        return Verdict.SUSPICIOUS, Confidence.MEDIUM
    return Verdict.SAFE,           Confidence.HIGH


def recommended_action(verdict: Verdict) -> str:
    return {
        Verdict.MALICIOUS:  "Do not click any links or open attachments. Report this email as phishing.",
        Verdict.SUSPICIOUS: "Exercise caution. Verify the sender through an official channel before taking action.",
        Verdict.LOW_RISK:   "This email has minor risk indicators. Review carefully before clicking any links.",
        Verdict.SAFE:       "No significant risk indicators detected.",
    }[verdict]


# Softer labels for low-risk verdicts - these patterns are normal in legitimate automated email.
_BENIGN_LABELS: dict[str, str] = {
    "INVISIBLE_TEXT":      "Invisible formatting characters detected (common in automated emails)",
    "GENERIC_GREETING":    "Email uses a general greeting rather than your name",
    "TRACKING_PIXEL":      "Email includes standard open-tracking (common in newsletters and notifications)",
    "URL_COMPLEXITY_RISK": "Email contains complex links (common in automated transactional emails)",
    "LINK_MISMATCH":       "Some links use redirects (standard in email marketing and notifications)",
    "URL_SHORTENER":       "A link uses a URL shortening service",
    "GEOLOCATION_RISK":    "The email was routed through a server in an unexpected location",
    "FINANCIAL_MANIP":     "The email mentions financial topics",
    "REPLY_MISMATCH":      "Replies are routed through a different address (common in business email systems)",
    "DOMAIN_NEW":          "The sender's domain was recently registered",
}

_SOFT_VERDICTS: frozenset[Verdict] = frozenset({Verdict.SAFE, Verdict.LOW_RISK})


def apply_context_aware_labels(signals: list[Signal], verdict: Verdict) -> list[Signal]:
    """
    Rewrites alarming signal labels to benign equivalents for SAFE/LOW_RISK verdicts.
    Never mutates the original list - the LLM always receives the unmodified signals.
    """
    if verdict not in _SOFT_VERDICTS:
        return signals
    return [
        dataclasses.replace(sig, label=_BENIGN_LABELS[sig.id])
        if sig.id in _BENIGN_LABELS
        else sig
        for sig in signals
    ]
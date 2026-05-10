"""
Strips invisible Unicode, removes CSS-hidden HTML, normalises URLs before any
third-party API call, and detects prompt-injection patterns.

If detect_prompt_injection() returns True, the caller must not forward email data to the LLM.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, urlunparse

from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
import warnings

from backend.models.request import EmailPayload, UrlEntry
from backend.services.signals import Signal

# Silence BeautifulSoup's "looks like a filename" warning on short strings
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)


# Characters used to hide text or defeat keyword filters:
#   U+200B  zero-width space          U+200C  ZW non-joiner
#   U+200D  ZW joiner                 U+00AD  soft hyphen
#   U+202E  RTL override              U+202D  LTR override
#   U+FEFF  BOM / ZW no-break space   U+2060  word joiner

_INVISIBLE_RE = re.compile(
    r"[​‌‍­‮‭﻿⁠]"
)


def remove_invisible_unicode(text: str) -> str:
    return _INVISIBLE_RE.sub("", text)



_HIDDEN_CSS_RE = re.compile(
    r"(font-size\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden|"
    r"opacity\s*:\s*0|"
    r"color\s*:\s*(white|#fff(?:fff)?)\b|"
    r"color\s*:\s*rgba?\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*0\s*\))",
    re.IGNORECASE,
)


def strip_hidden_text(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all(style=True):
        if _HIDDEN_CSS_RE.search(tag.get("style", "")):
            tag.decompose()
    return str(soup)


def extract_clean_text(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    raw  = soup.get_text(separator=" ")
    clean = re.sub(r"\s+", " ", raw).strip()
    return remove_invisible_unicode(clean)



# Strip before forwarding to Safe Browsing / VirusTotal - these params carry PII.
_STRIP_PARAMS_RE = re.compile(
    r"^(utm_\w+|fbclid|gclid|msclkid|mc_eid|_hsenc|_hsmi|"
    r"ref|source|affiliate|token|sessionid|sid|jsessionid|"
    r"PHPSESSID|access_token|auth_token|api_key)$",
    re.IGNORECASE,
)


def normalize_url_for_scanning(url: str) -> str:
    # Strips query params and fragment - no PII or session tokens reach third-party APIs.
    try:
        p = urlparse(url)
        return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))
    except Exception:
        return url


def normalize_urls(urls: list[UrlEntry]) -> list[UrlEntry]:
    # href is left intact here - normalise it per-call in threat_intel.py immediately before any API request.
    return [
        UrlEntry(
            display_text=remove_invisible_unicode(u.display_text),
            href=u.href,
        )
        for u in urls
    ]



_INJECTION_PATTERNS: list[str] = [
    r"ignore\s+(previous|above|all|prior)\s+instructions?",
    r"you\s+are\s+now\s+(a|an)\b",
    r"disregard\s+(your|all|the)",
    r"system\s+prompt",
    r"new\s+instructions?",
    r"forget\s+(everything|all|previous)",
    r"act\s+as\s+(a|an|if)\b",
    r"pretend\s+(to\s+be|you\s+are)",
    r"do\s+not\s+follow\s+(your|the)",
    r"override\s+(your|the)\s+(instructions?|rules?|guidelines?|constraints?)",
]

_INJECTION_RES: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE) for p in _INJECTION_PATTERNS
]


def detect_prompt_injection(text: str) -> tuple[bool, str]:
    # Returns (True, evidence_snippet) if a pattern matches; (False, "") otherwise.
    for rx in _INJECTION_RES:
        m = rx.search(text)
        if m:
            start = max(0, m.start() - 15)
            end   = min(len(text), m.end() + 15)
            evidence = "..." + text[start:end].strip() + "..."
            return True, evidence
    return False, ""



def sanitize(payload: EmailPayload) -> tuple[EmailPayload, list[Signal]]:
    """
    Sanitises all text fields and runs the injection gate.
    If PROMPT_INJECTION_ATTEMPT is in the returned signals, skip Layer 4.
    """
    extra_signals: list[Signal] = []

    # --- Strip invisible Unicode from user-visible text fields -------------
    clean_subject = remove_invisible_unicode(payload.subject)
    clean_display = remove_invisible_unicode(payload.sender.display_name)
    clean_urls    = normalize_urls(payload.urls)

    # Build a scan corpus from fields that will be forwarded to the LLM -
    # Deliberately excludes raw auth headers (structured data, not LLM input).
    scan_parts: list[str] = [
        clean_subject,
        clean_display,
        payload.sender.from_raw,
        *(u.display_text for u in clean_urls),
        *payload.body_signals.urgency_phrases,
        *payload.body_signals.credential_phrases,
        *payload.body_signals.financial_phrases,
        *payload.body_signals.otp_phrases,
    ]
    scan_corpus = " ".join(scan_parts)

    detected, evidence = detect_prompt_injection(scan_corpus)
    if detected:
        extra_signals.append(Signal(
            id="PROMPT_INJECTION_ATTEMPT",
            label="The email contains instructions designed to manipulate security analysis",
            weight=40,
            evidence=evidence,
        ))

    # Rebuild payload with sanitised fields
    sanitized_sender  = payload.sender.model_copy(update={"display_name": clean_display})
    sanitized_payload = payload.model_copy(update={
        "subject": clean_subject,
        "sender":  sanitized_sender,
        "urls":    clean_urls,
    })

    return sanitized_payload, extra_signals
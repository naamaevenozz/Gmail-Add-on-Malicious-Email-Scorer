from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from backend.models.request import AttachmentMeta, AuthResults, BodySignals, SenderInfo, UrlEntry



@dataclass
class Signal:
    id: str
    label: str
    weight: int
    evidence: Optional[str] = None
    count: int = 0



def check_spf(auth: AuthResults) -> list[Signal]:
    if auth.spf == "fail":
        return [Signal("SPF_FAIL", "The sending server is not authorized to send on behalf of this domain", 28, f"spf={auth.spf}")]
    return []


def check_spf_pass(auth: AuthResults) -> list[Signal]:
    if auth.spf == "pass":
        return [Signal("SPF_PASS", "The sending server is approved by the domain owner", 10)]
    return []


def check_dkim(auth: AuthResults) -> list[Signal]:
    if auth.dkim == "fail":
        return [Signal("DKIM_FAIL", "Could not verify sender identity", 32, f"dkim={auth.dkim}")]
    if auth.dkim == "none":
        # No DKIM at all is nearly as suspicious as a failed signature in 2024+.
        return [Signal("DKIM_FAIL", "Could not verify sender identity", 32, f"dkim={auth.dkim}")]
    return []


def check_dkim_pass(auth: AuthResults) -> list[Signal]:
    if auth.dkim == "pass":
        return [Signal("DKIM_PASS", "Sender identity verified", 15)]
    return []


def check_dmarc(auth: AuthResults) -> list[Signal]:
    if auth.dmarc == "fail":
        # Domain has an explicit policy and this email violated it - strongest auth signal.
        return [Signal("DMARC_FAIL", "This email failed the sender domain's own identity verification policy", 28, f"dmarc={auth.dmarc}")]
    if auth.dmarc == "none":
        # No DMARC policy at all - weaker signal, many legitimate domains lack one.
        return [Signal("DMARC_FAIL", "The sending domain has not set up sender verification standards", 20, f"dmarc={auth.dmarc}")]
    return []


def check_dmarc_pass(auth: AuthResults) -> list[Signal]:
    if auth.dmarc == "pass":
        return [Signal("DMARC_PASS", "The sender's identity meets official security standards", 8)]
    return []


def check_reply_to(sender: SenderInfo, auth: AuthResults) -> list[Signal]:
    # reply-to on a different domain is a common phishing tactic.
    if not auth.reply_to:
        return []
    reply_domain = _parse_domain(auth.reply_to)
    if reply_domain and reply_domain != sender.from_domain.lower():
        return [Signal(
            "REPLY_MISMATCH",
            "Replies to this email are directed to a completely different address",
            20,
            f"reply-to: {auth.reply_to} ≠ from domain: {sender.from_domain}",
        )]
    return []



_BRAND_DOMAINS: dict[str, set[str]] = {
    # Established brand domains
    "paypal":          {"paypal.com"},
    "google":          {"google.com", "gmail.com"},
    "amazon":          {"amazon.com", "amazon.co.uk", "amazon.de"},
    "microsoft":       {"microsoft.com", "outlook.com", "live.com", "hotmail.com"},
    "apple":           {"apple.com", "icloud.com"},
    "netflix":         {"netflix.com"},
    "chase":           {"chase.com"},
    "bankofamerica":   {"bankofamerica.com"},
    # Video / conferencing
    "zoom":            {"zoom.us", "zoom.com"},
    "webex":           {"webex.com", "cisco.com"},
    # Streaming / music
    "spotify":         {"spotify.com"},
    "youtube":         {"google.com", "youtube.com"},
    "twitch":          {"twitch.tv"},
    # Social / messaging
    "linkedin":        {"linkedin.com"},
    "twitter":         {"twitter.com", "x.com"},
    "facebook":        {"facebook.com", "facebookmail.com", "meta.com"},
    "instagram":       {"instagram.com"},
    "discord":         {"discord.com"},
    "whatsapp":        {"whatsapp.com"},
    # Developer / productivity
    "github":          {"github.com"},
    "gitlab":          {"gitlab.com"},
    "atlassian":       {"atlassian.com"},
    "jira":            {"atlassian.com"},
    "slack":           {"slack.com"},
    "notion":          {"notion.so"},
    "figma":           {"figma.com"},
    "dropbox":         {"dropbox.com"},
    # Cloud / enterprise SaaS
    "salesforce":      {"salesforce.com"},
    "hubspot":         {"hubspot.com"},
    "adobe":           {"adobe.com"},
    "docusign":        {"docusign.com"},
    "canva":           {"canva.com"},
    # E-commerce
    "shopify":         {"shopify.com"},
    "ebay":            {"ebay.com"},
    "etsy":            {"etsy.com"},
    # Financial / payments
    "venmo":           {"venmo.com"},
    "stripe":          {"stripe.com"},
    "americanexpress": {"americanexpress.com"},
    "wellsfargo":      {"wellsfargo.com"},
    "citibank":        {"citibank.com"},
    "capitalone":      {"capitalone.com"},
    "wise":            {"wise.com", "transferwise.com"},
}


def check_display_name(sender: SenderInfo) -> list[Signal]:
    name_lower = sender.display_name.lower()
    domain_lower = sender.from_domain.lower()
    for brand, trusted in _BRAND_DOMAINS.items():
        if re.search(rf"\b{re.escape(brand)}\b", name_lower):
            # Accept exact match or subdomain (e.g. accounts.google.com is trusted as Google).
            if not any(domain_lower == t or domain_lower.endswith("." + t) for t in trusted):
                return [Signal(
                    "DISPLAY_SPOOF",
                    f"Sender name claims to be '{brand}' but doesn't come from their actual domain",
                    30,
                    f"name='{sender.display_name}', domain={sender.from_domain}",
                )]
    return []


def _levenshtein(a: str, b: str) -> int:
    dp = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        ndp = [i + 1]
        for j, cb in enumerate(b):
            ndp.append(min(dp[j] + (ca != cb), dp[j + 1] + 1, ndp[-1] + 1))
        dp = ndp
    return dp[-1]


_HOMOGLYPH_BRANDS = [
    # Original high-value targets
    "paypal", "google", "amazon", "microsoft", "apple", "netflix",
    # Expanded - names long enough (≥5 chars) that 1-2 edits are meaningful
    "spotify", "linkedin", "twitter", "discord", "github", "gitlab",
    "dropbox", "shopify", "docusign", "salesforce", "instagram",
    "wellsfargo", "citibank", "capitalone", "americanexpress",
]


def check_homoglyph(domain: str) -> list[Signal]:
    # 0 < dist ≤ 2: similar enough to deceive, different enough to not be the real domain
    sld = domain.split(".")[0].lower()
    signals = []
    for brand in _HOMOGLYPH_BRANDS:
        dist = _levenshtein(sld, brand)
        if 0 < dist <= 2:
            signals.append(Signal(
                "HOMOGLYPH",
                f"The sender's address closely imitates '{brand}'",
                15,
                f"{domain} ≈ {brand}.com",
            ))
    return signals



_IP_URL_RE = re.compile(r"^https?://\d{1,3}(?:\.\d{1,3}){3}(?:[:/]|$)")

_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl",
    "short.link", "rb.gy", "is.gd", "buff.ly", "t.ly",
    "cutt.ly", "shorturl.at", "tiny.cc",
}

_HIGH_RISK_TLDS = {
    ".top", ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".lol", ".bond", ".sbs", ".icu", ".support", ".click",
    ".zip", ".mov",
}


def check_ip_urls(urls: list[UrlEntry]) -> list[Signal]:
    return [
        Signal("IP_URL", "A link in this email points directly to a numeric server address", 25, url.href)
        for url in urls
        if _IP_URL_RE.match(url.href)
    ]


def check_link_mismatch(urls: list[UrlEntry]) -> list[Signal]:
    signals = []
    for url in urls:
        text_domain = _domain_from_text(url.display_text)
        href_domain = _domain_from_href(url.href)
        # Compare registrable domains so that tracking subdomains like
        # bounce-sg.zoom.us vs zoom.us do not produce false positives.
        if text_domain and href_domain and _root_domain(text_domain) != _root_domain(href_domain):
            signals.append(Signal(
                "LINK_MISMATCH",
                "The link leads to a different site than the one shown in the text",
                10,
                f"text='{url.display_text}' - href={url.href}",
            ))
    return signals


def check_shorteners(urls: list[UrlEntry]) -> list[Signal]:
    return [
        Signal("URL_SHORTENER", "A link uses a shortener service that hides the real destination", 22, url.href)
        for url in urls
        if _domain_from_href(url.href) in _SHORTENER_DOMAINS
    ]


def check_punycode_domains(urls: list[UrlEntry]) -> list[Signal]:
    # IDN homograph attack: Cyrillic/Greek characters that look identical to Latin ones
    for url in urls:
        domain = _domain_from_href(url.href)
        if domain and _is_punycode_or_nonascii(domain):
            return [Signal(
                "PUNYCODE_DOMAIN",
                "A link uses deceptive characters to impersonate a known website",
                35,
                domain,
            )]
    return []


def check_suspicious_tld(sender: SenderInfo, urls: list[UrlEntry]) -> list[Signal]:
    """
    Flag sender domains and URL domains using TLDs statistically associated
    with phishing and malware distribution.
    """
    tld = _extract_tld(sender.from_domain)
    if tld in _HIGH_RISK_TLDS:
        return [Signal(
            "SUSPICIOUS_TLD",
            "The sender's domain uses an extension commonly linked to scam sites",
            20,
            sender.from_domain,
        )]
    for url in urls:
        domain = _domain_from_href(url.href)
        if domain:
            url_tld = _extract_tld(domain)
            if url_tld in _HIGH_RISK_TLDS:
                return [Signal(
                    "SUSPICIOUS_TLD",
                    "A link uses a domain extension commonly linked to scam sites",
                    20,
                    url.href,
                )]
    return []


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string - high values indicate random/generated text."""
    if not s:
        return 0.0
    from math import log2
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((count / n) * log2(count / n) for count in freq.values())


def check_url_complexity(urls: list[UrlEntry]) -> list[Signal]:
    # Requires ≥ 2 anomalies to fire - single heuristics have too many false positives on legitimate URLs.
    for url in urls:
        domain = _domain_from_href(url.href) or ""
        # Use only the registrable part (strip www / known subdomains)
        sld = domain.split(".")[0] if domain else ""

        score = 0
        reasons: list[str] = []

        entropy = _shannon_entropy(sld)
        if entropy > 3.5:
            score += 1
            reasons.append(f"domain entropy={entropy:.2f}")

        digit_count = sum(1 for c in sld if c.isdigit())
        if digit_count >= 4:
            score += 1
            reasons.append(f"{digit_count} digits in domain")

        hyphen_count = sld.count("-")
        if hyphen_count >= 2:
            score += 1
            reasons.append(f"{hyphen_count} hyphens in domain")

        if len(url.href) > 100:
            score += 1
            reasons.append(f"url_len={len(url.href)}")

        if score >= 2:
            return [Signal(
                "URL_COMPLEXITY_RISK",
                "The link address appears complex or intentionally hidden",
                18,
                "; ".join(reasons),
            )]
    return []



def check_urgency(body: BodySignals) -> list[Signal]:
    if len(body.urgency_phrases) >= 2:
        return [Signal(
            "URGENCY_HIGH",
            "The email uses language designed to pressure you into acting quickly",
            25,
            str(body.urgency_phrases),
        )]
    return []


def check_credentials(body: BodySignals) -> list[Signal]:
    if body.credential_phrases:
        return [Signal(
            "CRED_REQUEST",
            "The email asks for a password or personal account details",
            25,
            str(body.credential_phrases),
        )]
    return []


def check_financial(body: BodySignals) -> list[Signal]:
    if body.financial_phrases:
        return [Signal(
            "FINANCIAL_MANIP",
            "The email contains language designed to manipulate financial decisions",
            22,
            str(body.financial_phrases),
        )]
    return []


def check_invisible_text(body: BodySignals) -> list[Signal]:
    if body.has_invisible_text:
        return [Signal(
            "INVISIBLE_TEXT",
            "Hidden characters were found - a technique used to bypass security filters",
            30,
        )]
    return []


def check_generic_greeting(body: BodySignals) -> list[Signal]:
    if body.generic_greeting:
        return [Signal(
            "GENERIC_GREETING",
            "The email doesn't address you by name - likely sent to many people at once",
            30,
        )]
    return []


def check_fake_security_alert(body: BodySignals) -> list[Signal]:
    # The dismissal phrase ("if this was you, ignore this") is the tell - designed to disarm before the CTA.
    if body.fake_security_alert:
        return [Signal(
            "FAKE_SECURITY_ALERT",
            "The email impersonates a security warning to create a false sense of urgency",
            25,
        )]
    return []


def check_otp_request(body: BodySignals) -> list[Signal]:
    # Legitimate services never ask you to forward a code they sent you.
    if body.otp_phrases:
        return [Signal(
            "OTP_REQUEST",
            "The email asks you to share a one-time security code",
            24,
            str(body.otp_phrases),
        )]
    return []


def check_tracking_pixel(body: BodySignals, sender: SenderInfo) -> list[Signal]:
    # Weight is very low - virtually all legitimate marketing email uses tracking pixels.
    sender_root = _root_domain(sender.from_domain.lower())
    external = [d for d in body.tracking_pixel_domains if _root_domain(d) != sender_root]
    if external:
        return [Signal(
            "TRACKING_PIXEL",
            "The email includes a component that tracks when the message is opened",
            3,
            str(external[:3]),
        )]
    return []


def check_spelling_errors(body: BodySignals) -> list[Signal]:
    # Weight is low - AI-generated phishing now has perfect grammar
    if body.spelling_error_count >= 3:
        return [Signal(
            "SPELLING_ERRORS",
            f"The email contains {body.spelling_error_count} spelling or grammar mistakes",
            18,
            f"count={body.spelling_error_count}",
        )]
    return []



_MACRO_EXTENSIONS = {".xlsm", ".docm", ".xlam", ".pptm", ".xltm", ".dotm"}

_EXEC_MIME_TYPES = {
    "application/x-msdownload",
    "application/x-executable",
    "application/x-sh",
    "application/x-bat",
}

_DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".sh", ".cmd", ".com", ".scr",
    ".pif", ".vbs", ".js", ".jar", ".msi",
}


def check_attachments(attachments: list[AttachmentMeta]) -> list[Signal]:
    signals: list[Signal] = []
    for att in attachments:
        name_lower = att.filename.lower()
        parts = name_lower.split(".")

        # Double-extension: e.g. invoice.pdf.exe
        if len(parts) >= 3:
            last = f".{parts[-1]}"
            second_last = f".{parts[-2]}"
            if last in _DANGEROUS_EXTENSIONS and second_last not in _DANGEROUS_EXTENSIONS:
                signals.append(Signal(
                    "DOUBLE_EXT",
                    "An attachment is disguised using a misleading double file extension",
                    38,
                    att.filename,
                ))

        for ext in _MACRO_EXTENSIONS:
            if name_lower.endswith(ext):
                signals.append(Signal(
                    "MACRO_ENABLED",
                    "An attachment contains scripts that run automatically when opened",
                    25,
                    att.filename,
                ))
                break

        if att.mime_type in _EXEC_MIME_TYPES:
            signals.append(Signal(
                "EXEC_MIME",
                "An attachment is an executable program file",
                38,
                att.mime_type,
            ))

    return signals



def run_all(
    sender: SenderInfo,
    auth: AuthResults,
    urls: list[UrlEntry],
    attachments: list[AttachmentMeta],
    body: BodySignals,
) -> list[Signal]:
    # Same id + same evidence - deduplicated. Same id + different evidence - kept (e.g. three mismatched links).
    batches: list[list[Signal]] = [
        # Auth - risk signals
        check_spf(auth),
        check_dkim(auth),
        check_dmarc(auth),
        check_reply_to(sender, auth),
        # Auth - trust signals (apply as score discount in the aggregator)
        check_spf_pass(auth),
        check_dkim_pass(auth),
        check_dmarc_pass(auth),
        # Sender / domain
        check_display_name(sender),
        check_homoglyph(sender.from_domain),
        check_suspicious_tld(sender, urls),
        # URLs
        check_ip_urls(urls),
        check_link_mismatch(urls),
        check_shorteners(urls),
        check_punycode_domains(urls),
        check_url_complexity(urls),
        # Body / language
        check_urgency(body),
        check_credentials(body),
        check_financial(body),
        check_invisible_text(body),
        check_generic_greeting(body),
        check_fake_security_alert(body),
        check_otp_request(body),
        check_tracking_pixel(body, sender),
        check_spelling_errors(body),
        # Attachments
        check_attachments(attachments),
    ]

    seen: dict[tuple[str, str], Signal] = {}
    for batch in batches:
        for sig in batch:
            key = (sig.id, sig.evidence or "")
            if key not in seen:
                seen[key] = sig
    return list(seen.values())



_TWO_PART_TLDS: frozenset[str] = frozenset({
    "co.uk", "com.au", "co.in", "co.nz", "com.br", "co.jp",
    "co.za", "com.mx", "co.id", "com.tr", "co.kr",
})


def _root_domain(domain: str) -> str:
    """Return the registrable domain (eTLD+1) for a hostname.

    Examples: accounts.google.com -> google.com, bounce-sg.zoom.us -> zoom.us
    """
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain
    candidate = ".".join(parts[-2:])
    if candidate in _TWO_PART_TLDS:
        return ".".join(parts[-3:])
    return candidate


def _parse_domain(address: str) -> str | None:
    m = re.search(r"@([\w.-]+)", address)
    return m.group(1).lower() if m else None


def _domain_from_text(text: str) -> str | None:
    m = re.search(
        r"\b([\w-]+\.(?:com|org|net|io|co|uk|de|fr|gov|edu))\b",
        text,
        re.IGNORECASE,
    )
    return m.group(1).lower() if m else None


def _domain_from_href(href: str) -> str | None:
    m = re.match(r"https?://([^/:?\s]+)", href)
    return m.group(1).lower() if m else None


def _extract_tld(domain: str) -> str:
    """Return the last label of a domain as a dotted TLD string, e.g. '.xyz'."""
    parts = domain.rsplit(".", 1)
    return f".{parts[-1].lower()}" if len(parts) == 2 else ""


def _is_punycode_or_nonascii(domain: str) -> bool:
    """True if the domain uses Punycode encoding or contains non-ASCII characters."""
    if "xn--" in domain.lower():
        return True
    return any(ord(c) > 127 for c in domain)

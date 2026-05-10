"""
Network-backed checks. All API calls strip URL params before forwarding,
carry a 5-second timeout, and skip gracefully when the API key is absent.
"""
from __future__ import annotations

import asyncio
import base64
import os
from datetime import datetime, timezone

import httpx

from backend.models.request import UrlEntry
from backend.services.normalizer import normalize_url_for_scanning
from backend.services.signals import Signal

_TIMEOUT = httpx.Timeout(5.0)



# Google Safe Browsing v4
_SB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
_SB_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


async def check_safe_browsing(urls: list[UrlEntry]) -> list[Signal]:
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    if not api_key or not urls:
        return []

    clean_urls = [normalize_url_for_scanning(u.href) for u in urls]
    body = {
        "client": {"clientId": "email-risk-scorer", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes":      _SB_THREAT_TYPES,
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries":    [{"url": u} for u in clean_urls],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(f"{_SB_ENDPOINT}?key={api_key}", json=body)
        if resp.status_code != 200:
            return []
        matches = resp.json().get("matches", [])
        if not matches:
            return []
        flagged = {m["threat"]["url"] for m in matches}
        return [Signal(
            "SAFE_BROWSING",
            "One or more links are flagged as dangerous by Google's safety database",
            40,
            ", ".join(sorted(flagged)),
        )]
    except Exception:
        return []



# WHOIS domain-age check (whoisxmlapi.com)
_WHOIS_ENDPOINT  = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
_NEW_DOMAIN_DAYS = 30   # domains registered within this window are flagged


async def check_domain_age(domain: str) -> list[Signal]:
    api_key = os.getenv("WHOIS_XML_API_KEY")
    if not api_key or not domain:
        return []

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                _WHOIS_ENDPOINT,
                params={
                    "apiKey":       api_key,
                    "domainName":   domain,
                    "outputFormat": "JSON",
                },
            )
        if resp.status_code != 200:
            return []
        created_str = (
            resp.json()
                .get("WhoisRecord", {})
                .get("registryData", {})
                .get("createdDate", "")
        )
        if not created_str:
            return []
        created  = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - created).days
        if age_days < _NEW_DOMAIN_DAYS:
            return [Signal(
                "DOMAIN_NEW",
                f"The sender's domain was registered only {age_days} day(s) ago",
                20,
                f"{domain} registered {created.date()}",
            )]
        return []
    except Exception:
        return []



# VirusTotal v3 - URL reputation
_VT_URL_BASE      = "https://www.virustotal.com/api/v3/urls"
_VT_MALICIOUS_MIN = 3    # flag if >= 3 AV engines report malicious
_VT_MAX_URLS      = 3    # cap to stay within 4 req/min free-tier limit


async def check_virustotal(urls: list[UrlEntry]) -> list[Signal]:
    """
    GET VirusTotal v3 URL analysis for each URL (up to 3 to respect rate limits).
    Returns VIRUSTOTAL_HIT (weight=35) for each URL with >= 3 malicious votes.
    Skips when VIRUSTOTAL_API_KEY is not set.
    """


    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    print(f"DEBUG: VT API Key found: {bool(api_key)}")

    if not api_key or not urls:
        return []

    signals: list[Signal] = []
    for u in urls[:_VT_MAX_URLS]:
        clean  = normalize_url_for_scanning(u.href)
        url_id = base64.urlsafe_b64encode(clean.encode()).rstrip(b"=").decode()
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    f"{_VT_URL_BASE}/{url_id}",
                    headers={"x-apikey": api_key},
                )
            if resp.status_code != 200:
                continue
            stats = (
                resp.json()
                    .get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
            )
            malicious = stats.get("malicious", 0)
            if malicious >= _VT_MALICIOUS_MIN:
                signals.append(Signal(
                    "VIRUSTOTAL_HIT",
                    f"A link has been identified as dangerous by {malicious} independent security scanners",
                    35,
                    clean,
                    count=malicious,
                ))
        except Exception:
            continue
    return signals



# IP Geolocation - ip-api.com (free tier, no key required)
_GEO_ENDPOINT     = "http://ip-api.com/json/{ip}?fields=status,countryCode"
_HIGH_RISK_COUNTRIES = {"RU", "CN", "IR", "KP"}   # Russia, China, Iran, North Korea
_PRIVATE_PREFIXES = ("10.", "172.", "192.168.", "127.", "::1", "fc00:", "fd")


async def check_geolocation(sender_ip: str | None) -> list[Signal]:
    if not sender_ip:
        return []
    if any(sender_ip.startswith(prefix) for prefix in _PRIVATE_PREFIXES):
        return []

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(_GEO_ENDPOINT.format(ip=sender_ip))
        if resp.status_code != 200:
            return []
        data = resp.json()
        if data.get("status") != "success":
            return []
        country_code = data.get("countryCode", "")
        if country_code in _HIGH_RISK_COUNTRIES:
            return [Signal(
                "GEOLOCATION_RISK",
                "The email was sent from a server in a country associated with elevated cyber risk",
                15,
                f"ip={sender_ip}, country={country_code}",
            )]
        return []
    except Exception:
        return []



async def run_threat_intel(
    urls: list[UrlEntry],
    sender_domain: str,
    sender_ip: str | None = None,
) -> list[Signal]:
    # Deduplicates by signal id - highest weight wins on collision.
    batches = await asyncio.gather(
        check_safe_browsing(urls),
        check_domain_age(sender_domain),
        check_virustotal(urls),
        check_geolocation(sender_ip),
    )
    seen: dict[str, Signal] = {}
    for batch in batches:
        for sig in batch:
            if sig.id not in seen or sig.weight > seen[sig.id].weight:
                seen[sig.id] = sig
    return list(seen.values())
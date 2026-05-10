# -*- coding: utf-8 -*-
"""
Corpus Calibration Tool
=======================

Runs the email-scorer signal pipeline on the Nazario phishing corpus (malicious)
and the Enron ham corpus (legitimate), then compares manually set signal weights
against data-driven Logistic Regression coefficients.

OUTPUTS
-------
  <output>/signals_matrix.csv   -- One row per email: email_id, label, one binary
                                   column per signal ID (1 = fired, 0 = did not).
  <output>/weight_calibration.csv -- (requires scikit-learn + pandas) Comparison of
                                   manual weights vs. LR-derived weights, sorted by
                                   absolute delta, with fire rates per class.

USAGE
-----
    python tools/corpus_calibration.py \\
        --phishing  data/nazario  \\
        --legit     data/enron_ham \\
        --output    data/calibration_output \\
        --max-per-class 500

DOWNLOADING THE CORPORA
-----------------------
  Nazario Phishing Corpus
    Source: https://monkey.org/~jose/phishing/
    Format: individual .mbox files, one per year (e.g. phishing3.mbox)
    Place all .mbox files inside --phishing directory.

  Enron Ham Corpus (legitimate email)
    Source: https://www.cs.cmu.edu/~enron/  (enron_mail_20150507.tgz)
    Or from SpamAssassin easy_ham: https://spamassassin.apache.org/old/publiccorpus/
    Format: directory tree; each file is a raw RFC-2822 message.
    Point --legit at a sub-directory containing individual message files.

CAVEATS
-------
  Pre-2004 emails (both corpora) rarely have SPF / DKIM / DMARC headers.
  These auth signals will fire as "none" for phishing and ham alike, so
  DKIM_FAIL / DMARC_FAIL / SPF_FAIL will have near-zero LR coefficients
  even though they are strong signals for modern email.  The output notes
  this limitation in the console and marks affected signals in the CSV.
"""
from __future__ import annotations

import argparse
import csv
import email
import mailbox
import os
import re
import sys
from email.message import Message
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Path setup -- allow running from the project root
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
_BACKEND = _ROOT / "backend"
for _p in [str(_ROOT), str(_BACKEND)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from bs4 import BeautifulSoup  # type: ignore
    _BS4_AVAILABLE = True
except ImportError:
    _BS4_AVAILABLE = False
    print("[WARNING] beautifulsoup4 not installed -- HTML URL extraction disabled.")

from backend.services.aggregator import SIGNAL_TO_CATEGORY, aggregate
from backend.services.signals import run_all
from backend.models.request import (
    AttachmentMeta, AuthResults, BodySignals, SenderInfo, UrlEntry,
)


# ---------------------------------------------------------------------------
# Phrase patterns for body-signal extraction
# (mirrors what a production frontend / API would extract before sending)
# ---------------------------------------------------------------------------

_URGENCY_PATTERNS = [
    r"\bact\s+(?:now|immediately|today|urgently)\b",
    r"\bimmediate\s+action\s+required\b",
    r"\bwithin\s+\d+\s+(?:hours?|days?)\b",
    r"\baccount\s+(?:will\s+be\s+)?(?:suspended|closed|blocked|disabled|terminated)\b",
    r"\bexpires?\s+(?:soon|today|in\s+\d+)\b",
    r"\blast\s+(?:chance|warning|notice|reminder)\b",
    r"\burgent(?:ly)?\b.*\b(?:verify|confirm|update|respond)\b",
    r"\b(?:verify|confirm|update)\s+(?:your\s+)?(?:account|information|details)\s+(?:now|immediately)\b",
    r"\blimited\s+time\b",
    r"\bfailure\s+to\s+(?:comply|respond|verify)\b",
    r"\baction\s+required\b",
    r"\bresponse\s+needed\b",
    r"\bdo\s+not\s+(?:ignore|delay)\s+this\b",
    r"\bnotice\s+of\s+suspension\b",
]

_CREDENTIAL_PATTERNS = [
    r"\benter\s+(?:your\s+)?(?:password|username|login|credentials?|pin)\b",
    r"\bconfirm\s+(?:your\s+)?(?:password|credentials?|identity)\b",
    r"\bsign\s+in\s+(?:to\s+)?(?:your\s+account|verify|confirm)\b",
    r"\bclick\s+(?:here\s+to\s+)?(?:login|log\s+in|sign\s+in|verify)\b",
    r"\bverify\s+(?:your\s+)?(?:account|identity|email|information)\b",
    r"\bupdate\s+(?:your\s+)?(?:password|account\s+information|billing)\b",
    r"\bsecurity\s+(?:verification|check|update)\s+required\b",
    r"\baccount\s+(?:verification|confirmation)\s+(?:needed|required)\b",
    r"\bprovide\s+(?:your\s+)?(?:personal|account|login)\s+(?:information|details|data)\b",
    r"\bsubmit\s+(?:your\s+)?(?:information|details|credentials?)\b",
    r"\brevalidate\b",
    r"\breactivate\s+(?:your\s+)?account\b",
]

_FINANCIAL_PATTERNS = [
    r"\b\$\s*\d[\d,\.]+\s*(?:million|billion|USD|dollars?)?\b",
    r"\b\d+\s*(?:million|billion)\s+(?:USD|dollars?|pounds?|euros?)\b",
    r"\bwire\s+transfer\b",
    r"\bbank\s+(?:account|transfer|details)\b",
    r"\btransfer\s+(?:fee|funds?|money|amount)\b",
    r"\badvance\s+(?:fee|payment)\b",
    r"\bnext\s+of\s+kin\b",
    r"\bbusiness\s+(?:partnership|proposal|transaction)\b",
    r"\bcompensation\s+(?:fund|payment|transfer)\b",
    r"\bunclaimed\s+(?:funds?|inheritance|money)\b",
    r"\bbeneficiary\b",
    r"\btrust\s+(?:fund|account)\b",
    r"\bfund\s+release\b",
    r"\boverdue\s+(?:invoice|payment|bill)\b",
    r"\brefund\s+(?:pending|available|credit)\b",
    r"\binvoice\s+(?:attached|enclosed|#\d+)\b",
    r"\bpayment\s+(?:required|due|overdue|pending|confirmation)\b",
]

_OTP_PATTERNS = [
    r"\bone[- ]time\s+(?:password|code|passcode|pin)\b",
    r"\bverification\s+code\b",
    r"\bsecurity\s+code\b",
    r"\botp\b",
    r"\b2fa\b",
    r"\benter\s+(?:the\s+)?code\b",
    r"\bauthentication\s+code\b",
    r"\bconfirmation\s+code\b",
    r"\btwo[- ]factor\b",
    r"\bforward\s+(?:the\s+)?code\b",
    r"\bshare\s+(?:the\s+)?code\b",
    r"\bsend\s+(?:us\s+)?(?:the\s+)?code\b",
]

_GENERIC_GREETING_RE = re.compile(
    r"^\s*(?:dear\s+(?:customer|user|client|member|valued\s+(?:customer|member|client)|"
    r"account\s+(?:holder|owner)|sir|ma'?am|sir\/madam|friend|beneficiary|"
    r"associate|partner|colleague)|hello\s+(?:there|customer|user)|"
    r"greetings\s+(?:from|dear)?|attention\s+(?:valued\s+)?(?:customer|user|member))",
    re.IGNORECASE | re.MULTILINE,
)

_FAKE_SECURITY_RE = re.compile(
    r"(?:"
    r"unusual\s+(?:sign[- ]in|login|activity|access)\s+(?:detected|attempt)"
    r"|suspicious\s+(?:activity|login|sign[- ]in)\s+(?:detected|on\s+your)"
    r"|someone\s+(?:tried\s+to|attempted\s+to)\s+(?:access|log)"
    r"|unauthorized\s+(?:access|login|activity)"
    r"|your\s+account\s+(?:has\s+been\s+)?(?:compromised|hacked|accessed)"
    r"|if\s+this\s+was(?:n'?t|\s+not)\s+you"
    r"|if\s+you\s+did(?:n'?t|\s+not)\s+(?:make|request|initiate)"
    r"|security\s+alert\s+for\s+your\s+account"
    r")",
    re.IGNORECASE,
)

_INVISIBLE_UNICODE_RE = re.compile(
    # zero-width space(200B), ZW non-joiner(200C), ZW joiner(200D),
    # soft-hyphen(00AD), RTL override(202E), LTR override(202D),
    # BOM/ZW-no-break(FEFF), word-joiner(2060)
    "[\u200b\u200c\u200d\u00ad\u202e\u202d\ufeff\u2060]"
)

_IP_URL_RE = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}(?:[:/]|$)")
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl",
    "short.link", "rb.gy", "is.gd", "buff.ly", "t.ly",
    "cutt.ly", "shorturl.at", "tiny.cc",
}

_AUTH_HEADER_RE = re.compile(
    r"(?:spf|dkim|dmarc)\s*=\s*(pass|fail|none|neutral|temperror|permerror|"
    r"softfail|hardfail)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Email parser
# ---------------------------------------------------------------------------

def _get_payload_text(msg: Message) -> tuple[str, str]:
    """Return (plain_text, html_text) from an email.Message."""
    plain, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get("Content-Disposition", ""))
            if "attachment" in cd:
                continue
            charset = part.get_content_charset() or "utf-8"
            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                text = payload.decode(charset, errors="replace")
            except Exception:
                continue
            if ct == "text/plain" and not plain:
                plain = text
            elif ct == "text/html" and not html:
                html = text
    else:
        ct = msg.get_content_type()
        charset = msg.get_content_charset() or "utf-8"
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                text = payload.decode(charset, errors="replace")
                if ct == "text/html":
                    html = text
                else:
                    plain = text
        except Exception:
            pass
    return plain, html


def _extract_urls_from_html(html: str) -> list[UrlEntry]:
    """Parse anchor tags from HTML using BeautifulSoup when available."""
    entries: list[UrlEntry] = []
    if not html:
        return entries
    if _BS4_AVAILABLE:
        try:
            soup = BeautifulSoup(html, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                text = a.get_text(strip=True) or href
                if href.startswith("http"):
                    entries.append(UrlEntry(display_text=text[:200], href=href[:500]))
        except Exception:
            pass
    else:
        for href in _URL_RE.findall(html):
            entries.append(UrlEntry(display_text=href[:200], href=href[:500]))
    return entries


def _extract_urls_from_text(text: str) -> list[UrlEntry]:
    """Extract bare URLs from plain text."""
    entries: list[UrlEntry] = []
    for href in _URL_RE.findall(text or ""):
        href = href.rstrip(".,;)")
        entries.append(UrlEntry(display_text=href[:200], href=href[:500]))
    return entries


def _parse_auth_results(msg: Message) -> tuple[str, str, str]:
    """
    Extract spf/dkim/dmarc results from Authentication-Results headers.
    Returns ('pass'|'fail'|'none', ...) for each.
    Historical emails (pre-2004) rarely have these -- default to 'none'.
    """
    spf = dkim = dmarc = "none"
    for header_val in msg.get_all("Authentication-Results", []) + msg.get_all("X-Authentication-Results", []):
        header_lower = header_val.lower()
        for match in _AUTH_HEADER_RE.finditer(header_val):
            full = match.group(0).lower()
            result = match.group(1).lower()
            if result not in ("pass", "fail", "none"):
                result = "fail" if "fail" in result else "none"
            if "spf" in full and spf == "none":
                spf = result
            elif "dkim" in full and dkim == "none":
                dkim = result
            elif "dmarc" in full and dmarc == "none":
                dmarc = result
    # Also check Received-SPF header as a fallback
    for header_val in msg.get_all("Received-SPF", []):
        header_lower = header_val.lower().strip()
        if header_lower.startswith("pass") and spf == "none":
            spf = "pass"
        elif header_lower.startswith("fail") and spf == "none":
            spf = "fail"
    return spf, dkim, dmarc


def _extract_phrases(text: str, patterns: list[str]) -> list[str]:
    matched: list[str] = []
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            matched.append(m.group(0)[:100])
    return matched


def _count_spelling_errors(text: str) -> int:
    """
    Count misspellings of security/account vocabulary common in phishing.
    Intentionally narrow: only known phishing-specific misspellings.
    """
    _MISSPELL_RE = re.compile(
        r"\b(?:accoount|acccount|verifiy|verifcation|passw0rd|pasword|"
        r"suspeneded|susppended|unauthoriized|autentication|confrim|"
        r"recieve|immediatly|acccess|informations|kindly\s+revert|"
        r"beneficary|transactoin|instution)\b",
        re.IGNORECASE,
    )
    return len(_MISSPELL_RE.findall(text))


def _has_invisible_text(text: str) -> bool:
    return bool(_INVISIBLE_UNICODE_RE.search(text))


def _parse_sender(msg: Message) -> tuple[str, str, str]:
    """Return (from_raw, from_domain, display_name)."""
    from_raw = msg.get("From", "unknown@unknown.com")
    # Parse display name and address
    from email.utils import parseaddr
    display_name, addr = parseaddr(from_raw)
    if not addr:
        addr = from_raw
    domain = addr.split("@")[-1].lower().strip(">") if "@" in addr else "unknown.com"
    domain = re.sub(r"[^a-z0-9.\-]", "", domain) or "unknown.com"
    display_name = display_name or addr.split("@")[0]
    return from_raw[:500], domain, display_name[:200]


def _parse_attachments(msg: Message) -> list[AttachmentMeta]:
    attachments: list[AttachmentMeta] = []
    if not msg.is_multipart():
        return attachments
    for part in msg.walk():
        cd = str(part.get("Content-Disposition", ""))
        if "attachment" not in cd:
            continue
        filename = part.get_filename() or "unknown"
        mime_type = part.get_content_type() or "application/octet-stream"
        payload = part.get_payload(decode=True) or b""
        attachments.append(AttachmentMeta(
            filename=filename[:200],
            mime_type=mime_type,
            size_bytes=len(payload),
        ))
    return attachments


def parse_message(msg: Message, email_id: str) -> tuple[
    SenderInfo, AuthResults, list[UrlEntry], list[AttachmentMeta], BodySignals
]:
    """Convert a raw email.Message into the five inputs expected by run_all()."""
    from_raw, domain, display_name = _parse_sender(msg)
    spf, dkim, dmarc = _parse_auth_results(msg)

    reply_to = msg.get("Reply-To", None)
    if reply_to:
        reply_to = reply_to.strip()[:200]

    sender = SenderInfo(from_raw=from_raw, from_domain=domain, display_name=display_name)
    auth   = AuthResults(spf=spf, dkim=dkim, dmarc=dmarc, reply_to=reply_to)

    plain, html = _get_payload_text(msg)
    body_text = plain or ""
    if not body_text and html:
        if _BS4_AVAILABLE:
            try:
                body_text = BeautifulSoup(html, "html.parser").get_text(separator=" ")
            except Exception:
                body_text = re.sub(r"<[^>]+>", " ", html)
        else:
            body_text = re.sub(r"<[^>]+>", " ", html)

    # Collect URLs from both HTML anchors and plain-text bare links
    urls: list[UrlEntry] = []
    seen_hrefs: set[str] = set()
    for entry in _extract_urls_from_html(html) + _extract_urls_from_text(body_text):
        if entry.href not in seen_hrefs:
            seen_hrefs.add(entry.href)
            urls.append(entry)

    attachments = _parse_attachments(msg)

    # Extract body-signal primitives from the combined text
    full_text = f"{msg.get('Subject', '')} {body_text}"

    urgency_phrases     = _extract_phrases(full_text, _URGENCY_PATTERNS)
    credential_phrases  = _extract_phrases(full_text, _CREDENTIAL_PATTERNS)
    financial_phrases   = _extract_phrases(full_text, _FINANCIAL_PATTERNS)
    otp_phrases         = _extract_phrases(full_text, _OTP_PATTERNS)
    generic_greeting    = bool(_GENERIC_GREETING_RE.search(body_text[:500]))
    fake_security_alert = bool(_FAKE_SECURITY_RE.search(full_text))
    has_invisible       = _has_invisible_text(full_text)
    spelling_errors     = _count_spelling_errors(full_text)

    body = BodySignals(
        char_count=len(body_text),
        urgency_phrases=urgency_phrases,
        credential_phrases=credential_phrases,
        financial_phrases=financial_phrases,
        otp_phrases=otp_phrases,
        has_invisible_text=has_invisible,
        generic_greeting=generic_greeting,
        fake_security_alert=fake_security_alert,
        spelling_error_count=spelling_errors,
    )

    return sender, auth, urls, attachments, body


# ---------------------------------------------------------------------------
# Corpus loaders
# ---------------------------------------------------------------------------

def _load_mbox(path: Path, max_count: int) -> list[tuple[str, Message]]:
    """Load messages from an mbox file."""
    results: list[tuple[str, Message]] = []
    try:
        mbox = mailbox.mbox(str(path))
        for i, msg in enumerate(mbox):
            if len(results) >= max_count:
                break
            results.append((f"{path.stem}_{i}", msg))
    except Exception as exc:
        print(f"  [ERROR] Could not read mbox {path}: {exc}")
    return results


def _load_directory(root: Path, max_count: int) -> list[tuple[str, Message]]:
    """Load individual RFC-2822 message files from a directory tree."""
    results: list[tuple[str, Message]] = []
    for dirpath, _, filenames in os.walk(str(root)):
        for fname in sorted(filenames):
            if len(results) >= max_count:
                return results
            fpath = Path(dirpath) / fname
            if fpath.suffix.lower() in {".json", ".csv", ".py", ".md", ".txt", ".log"}:
                continue
            try:
                raw = fpath.read_bytes()
                msg = email.message_from_bytes(raw)
                if not msg.get("From") and not msg.get("Date"):
                    continue  # skip non-email files
                rel = fpath.relative_to(root)
                eid = str(rel).replace("\\", "/").replace("/", "__")
                results.append((eid, msg))
            except Exception:
                continue
    return results


def _load_corpus(corpus_path: str, label: str, max_count: int) -> list[tuple[str, int, Message]]:
    """
    Load up to max_count messages from corpus_path.
    Returns list of (email_id, label, message).
    """
    root = Path(corpus_path)
    if not root.exists():
        print(f"[ERROR] Corpus path not found: {corpus_path}")
        return []

    raw_pairs: list[tuple[str, Message]] = []

    if root.is_file() and root.suffix.lower() == ".mbox":
        raw_pairs = _load_mbox(root, max_count)
    elif root.is_dir():
        # Look for mbox files first, then fall back to directory of files
        mbox_files = list(root.glob("*.mbox"))
        if mbox_files:
            for mbox_path in sorted(mbox_files):
                if len(raw_pairs) >= max_count:
                    break
                batch = _load_mbox(mbox_path, max_count - len(raw_pairs))
                raw_pairs.extend(batch)
        else:
            raw_pairs = _load_directory(root, max_count)
    else:
        print(f"[ERROR] Unknown corpus format: {corpus_path}")
        return []

    print(f"  Loaded {len(raw_pairs)} {label} messages from {corpus_path}")
    return [(eid, int(label == "phishing"), msg) for eid, msg in raw_pairs]


# ---------------------------------------------------------------------------
# Main processing loop
# ---------------------------------------------------------------------------

ALL_SIGNAL_IDS = sorted(SIGNAL_TO_CATEGORY.keys())


def process_corpus(
    phishing_path: str,
    legit_path: str,
    max_per_class: int,
    output_dir: str,
) -> None:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    print("\n=== Loading corpora ===")
    phishing_emails = _load_corpus(phishing_path, "phishing", max_per_class)
    legit_emails    = _load_corpus(legit_path,    "legit",    max_per_class)
    all_emails      = phishing_emails + legit_emails

    if not all_emails:
        print("[ERROR] No emails loaded. Exiting.")
        return

    print(f"\n=== Processing {len(all_emails)} emails ===")
    rows: list[dict] = []
    errors = 0

    for i, (eid, label, msg) in enumerate(all_emails):
        if i % 100 == 0:
            print(f"  [{i}/{len(all_emails)}] ...")
        try:
            sender, auth, urls, attachments, body = parse_message(msg, eid)
            signals = run_all(sender, auth, urls, attachments, body)
            score, breakdown = aggregate(signals)
            fired_ids = {s.id for s in signals}

            row: dict = {"email_id": eid, "label": label, "score": score}
            for sid in ALL_SIGNAL_IDS:
                row[sid] = 1 if sid in fired_ids else 0
            rows.append(row)
        except Exception as exc:
            errors += 1
            if errors <= 10:
                print(f"  [WARN] Failed to process {eid}: {exc}")

    print(f"\n  Done. {len(rows)} processed, {errors} errors.")

    # ----- Write signals_matrix.csv -----------------------------------------
    matrix_path = out / "signals_matrix.csv"
    fieldnames = ["email_id", "label", "score"] + ALL_SIGNAL_IDS
    with open(matrix_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"\n  Written: {matrix_path}")

    # ----- Basic stats -------------------------------------------------------
    phishing_rows = [r for r in rows if r["label"] == 1]
    legit_rows    = [r for r in rows if r["label"] == 0]
    if phishing_rows:
        avg_phishing = sum(r["score"] for r in phishing_rows) / len(phishing_rows)
        above_60     = sum(1 for r in phishing_rows if r["score"] >= 60)
        above_75     = sum(1 for r in phishing_rows if r["score"] >= 75)
        print(f"\n  Phishing ({len(phishing_rows)} emails):")
        print(f"    Avg score:    {avg_phishing:.1f}")
        print(f"    Score >= 60:  {above_60}/{len(phishing_rows)} ({100*above_60/len(phishing_rows):.0f}%)")
        print(f"    Score >= 75:  {above_75}/{len(phishing_rows)} ({100*above_75/len(phishing_rows):.0f}%)")
    if legit_rows:
        avg_legit  = sum(r["score"] for r in legit_rows) / len(legit_rows)
        false_pos  = sum(1 for r in legit_rows if r["score"] >= 51)
        print(f"\n  Legit ({len(legit_rows)} emails):")
        print(f"    Avg score:       {avg_legit:.1f}")
        print(f"    False-positive:  {false_pos}/{len(legit_rows)} (score>=51) ({100*false_pos/len(legit_rows):.0f}%)")

    # ----- Logistic Regression (optional) -----------------------------------
    _run_logistic_regression(rows, out)

    print("\nDone.")


def _run_logistic_regression(rows: list[dict], out: Path) -> None:
    """Fit LR on the binary signal matrix and compare to manual weights."""
    try:
        import numpy as np                      # type: ignore
        import pandas as pd                     # type: ignore
        from sklearn.linear_model import LogisticRegression  # type: ignore
        from sklearn.preprocessing import StandardScaler     # type: ignore
    except ImportError:
        print("\n[INFO] scikit-learn / pandas / numpy not installed.")
        print("       Install them to enable weight calibration analysis:")
        print("       pip install scikit-learn pandas numpy")
        return

    from backend.services.aggregator import SIGNAL_TO_CATEGORY as S2C
    from backend.services.signals import (
        check_spf, check_dkim, check_dmarc, check_reply_to,
        check_display_name, check_homoglyph, check_suspicious_tld,
        check_ip_urls, check_link_mismatch, check_shorteners,
        check_punycode_domains, check_urgency, check_credentials,
        check_financial, check_invisible_text, check_generic_greeting,
        check_fake_security_alert, check_otp_request, check_spelling_errors,
        check_attachments,
    )

    # Reconstruct manual weight table from signal module defaults
    # (these are the weights used in the live pipeline)
    from backend.models.request import (
        AuthResults as AR, SenderInfo as SI, UrlEntry as UE,
        AttachmentMeta as AM, BodySignals as BS,
    )

    # Build a probe map: signal_id -> a sample invocation that fires it
    _PROBE_WEIGHTS: dict[str, int] = {}

    def _probe(sig_list):
        for s in sig_list:
            if s.id not in _PROBE_WEIGHTS:
                _PROBE_WEIGHTS[s.id] = s.weight

    _probe(check_spf(AR(spf="fail", dkim="none", dmarc="none")))
    _probe(check_dkim(AR(spf="none", dkim="fail", dmarc="none")))
    _probe(check_dmarc(AR(spf="none", dkim="none", dmarc="fail")))
    _probe(check_dkim(AR(spf="none", dkim="none", dmarc="none")))
    _probe(check_dmarc(AR(spf="none", dkim="none", dmarc="none")))
    _probe(check_reply_to(SI(from_raw="a@x.com", from_domain="x.com", display_name="X"),
                          AR(spf="none", dkim="none", dmarc="none", reply_to="other@y.com")))
    _probe(check_display_name(SI(from_raw="a@evil.com", from_domain="evil.com", display_name="PayPal")))
    _probe(check_homoglyph("paypa1.com"))
    _probe(check_ip_urls([UE(display_text="click", href="http://1.2.3.4/path")]))
    _probe(check_link_mismatch([UE(display_text="paypal.com", href="http://evil.com/phish")]))
    _probe(check_shorteners([UE(display_text="click", href="http://bit.ly/xyz")]))
    _probe(check_punycode_domains([UE(display_text="click", href="http://xn--pypal-4ve.com/")]))
    _probe(check_urgency(BS(char_count=100, urgency_phrases=["act now", "expires today"])))
    _probe(check_credentials(BS(char_count=100, credential_phrases=["enter your password"])))
    _probe(check_financial(BS(char_count=100, financial_phrases=["wire transfer"])))
    _probe(check_invisible_text(BS(char_count=100, has_invisible_text=True)))
    _probe(check_generic_greeting(BS(char_count=100, generic_greeting=True)))
    _probe(check_fake_security_alert(BS(char_count=100, fake_security_alert=True)))
    _probe(check_otp_request(BS(char_count=100, otp_phrases=["enter code"])))
    _probe(check_spelling_errors(BS(char_count=100, spelling_error_count=5)))
    _probe(check_attachments([AM(filename="invoice.pdf.exe", mime_type="application/octet-stream", size_bytes=1000)]))
    _probe(check_attachments([AM(filename="budget.xlsm", mime_type="application/vnd.ms-excel.sheet.macroenabled.12", size_bytes=1000)]))
    _probe(check_attachments([AM(filename="tool.exe", mime_type="application/x-msdownload", size_bytes=1000)]))

    print("\n=== Logistic Regression Weight Calibration ===")
    print("  NOTE: Auth signals (DKIM_FAIL, DMARC_FAIL, SPF_FAIL) may show low LR")
    print("  coefficients because pre-2004 corpus emails lack these headers -- both")
    print("  phishing and ham will have auth='none' equally, masking the signal.\n")

    df = pd.DataFrame(rows)
    if df["label"].nunique() < 2:
        print("  [WARN] Only one class present -- cannot fit LR. Skipping.")
        return

    X = df[ALL_SIGNAL_IDS].values.astype(float)
    y = df["label"].values

    lr = LogisticRegression(
        class_weight="balanced",
        max_iter=1000,
        solver="lbfgs",
        C=1.0,
    )
    try:
        lr.fit(X, y)
    except Exception as exc:
        print(f"  [ERROR] LR fitting failed: {exc}")
        return

    coefs = lr.coef_[0]

    # Normalize LR coefficients to 0-40 scale matching manual weights
    # Map max positive coef -> 40, min (most negative / irrelevant) -> 0
    pos_coefs = np.clip(coefs, 0, None)
    coef_max = pos_coefs.max() if pos_coefs.max() > 0 else 1.0
    lr_weights_normalized = (pos_coefs / coef_max * 40).round(1)

    # Fire rates per class
    phishing_mask = y == 1
    ham_mask      = y == 0
    fire_phishing = X[phishing_mask].mean(axis=0) * 100
    fire_ham      = X[ham_mask].mean(axis=0)      * 100

    calibration_rows = []
    for i, sid in enumerate(ALL_SIGNAL_IDS):
        manual_w = _PROBE_WEIGHTS.get(sid, 0)
        lr_w     = lr_weights_normalized[i]
        delta    = lr_w - manual_w
        calibration_rows.append({
            "Signal":              sid,
            "Category":            S2C.get(sid, "N/A"),
            "Manual_Weight":       manual_w,
            "LR_Coefficient":      round(float(coefs[i]), 4),
            "LR_Weight_0to40":     lr_w,
            "Delta":               round(float(delta), 1),
            "Fire_Rate_Phishing%": round(float(fire_phishing[i]), 1),
            "Fire_Rate_Ham%":      round(float(fire_ham[i]), 1),
        })

    cal_df = pd.DataFrame(calibration_rows).sort_values("Delta", key=abs, ascending=False)

    cal_path = out / "weight_calibration.csv"
    try:
        cal_df.to_csv(cal_path, index=False)
    except PermissionError:
        from datetime import datetime
        cal_path = out / f"weight_calibration_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        cal_df.to_csv(cal_path, index=False)
        print(f"  [WARN] weight_calibration.csv is locked (open in Excel?); wrote to fallback.")
    print(f"  Written: {cal_path}")

    # Print a summary table of the biggest discrepancies
    print(f"\n  {'Signal':<30} {'Manual':>6} {'LR_0-40':>7} {'Delta':>6}  {'Phish%':>6} {'Ham%':>5}")
    print("  " + "-" * 65)
    for _, r in cal_df.head(20).iterrows():
        marker = " <-- over-calibrated" if r["Delta"] < -8 else (" <-- under-calibrated" if r["Delta"] > 8 else "")
        print(
            f"  {r['Signal']:<30} {r['Manual_Weight']:>6} {r['LR_Weight_0to40']:>7} "
            f"{r['Delta']:>+6.1f}  {r['Fire_Rate_Phishing%']:>5.1f}% {r['Fire_Rate_Ham%']:>4.1f}%"
            f"{marker}"
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Corpus calibration: validate email-scorer signal weights against real data.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--phishing",      required=True,  help="Path to Nazario phishing corpus (dir or .mbox file)")
    parser.add_argument("--legit",         required=True,  help="Path to Enron ham corpus directory")
    parser.add_argument("--max-per-class", type=int, default=500, metavar="N",
                        help="Max emails per class (default: 500)")
    parser.add_argument("--output",        default="data/calibration_output",
                        help="Output directory for CSV files (default: data/calibration_output)")
    args = parser.parse_args()

    process_corpus(
        phishing_path=args.phishing,
        legit_path=args.legit,
        max_per_class=args.max_per_class,
        output_dir=args.output,
    )


if __name__ == "__main__":
    main()

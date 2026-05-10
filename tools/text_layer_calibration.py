# -*- coding: utf-8 -*-
"""
Text Layer Calibration
======================

Calibrates the language_risk signal weights using a labeled email text dataset.

Reads a CSV with columns: text, label, phishing_type, severity, confidence
  label 0 = legitimate
  label 1 = phishing

For each row it extracts body signals from the raw text using the same regex
patterns used in production, runs only the language-risk signal checks, and
fits a Logistic Regression to derive data-driven weights.

OUTPUTS
-------
  <output>/text_layer_signals.csv      -- Binary signal matrix (one row per email)
  <output>/text_layer_calibration.csv  -- LR weights vs manual weights
  <output>/text_layer_report.txt       -- Human-readable summary + recommendations

USAGE
-----
    python tools/text_layer_calibration.py \\
        --csv  data/phishing_legit_dataset_KD_10000.csv \\
        --output data/calibration_output
"""
from __future__ import annotations

import argparse
import csv
import re
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
_BACKEND = _ROOT / "backend"
for _p in [str(_ROOT), str(_BACKEND)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from backend.models.request import BodySignals
from backend.services.signals import (
    check_urgency, check_credentials, check_financial,
    check_generic_greeting, check_fake_security_alert,
    check_otp_request, check_spelling_errors,
)

# Signal definitions - ID - (check_fn, current manual weight)

LANGUAGE_SIGNALS: dict[str, int] = {
    "URGENCY_HIGH":       10,
    "CRED_REQUEST":       25,
    "FINANCIAL_MANIP":    22,
    "GENERIC_GREETING":   20,
    "FAKE_SECURITY_ALERT": 25,
    "OTP_REQUEST":        18,
    "SPELLING_ERRORS":    18,
}

# Regex patterns

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

_MISSPELL_RE = re.compile(
    r"\b(?:accoount|acccount|verifiy|verifcation|passw0rd|pasword|"
    r"suspeneded|susppended|unauthoriized|autentication|confrim|"
    r"recieve|immediatly|acccess|informations|kindly\s+revert|"
    r"beneficary|transactoin|instution)\b",
    re.IGNORECASE,
)


def _extract_phrases(text: str, patterns: list[str]) -> list[str]:
    matched = []
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            matched.append(m.group(0)[:100])
    return matched


def _text_to_body_signals(text: str) -> BodySignals:
    urgency_phrases    = _extract_phrases(text, _URGENCY_PATTERNS)
    credential_phrases = _extract_phrases(text, _CREDENTIAL_PATTERNS)
    financial_phrases  = _extract_phrases(text, _FINANCIAL_PATTERNS)
    otp_phrases        = _extract_phrases(text, _OTP_PATTERNS)
    generic_greeting   = bool(_GENERIC_GREETING_RE.search(text[:500]))
    fake_security      = bool(_FAKE_SECURITY_RE.search(text))
    spelling_errors    = len(_MISSPELL_RE.findall(text))

    return BodySignals(
        char_count=len(text),
        urgency_phrases=urgency_phrases,
        credential_phrases=credential_phrases,
        financial_phrases=financial_phrases,
        otp_phrases=otp_phrases,
        generic_greeting=generic_greeting,
        fake_security_alert=fake_security,
        spelling_error_count=spelling_errors,
    )



def run(csv_path: str, output_dir: str) -> None:
    try:
        import numpy as np
        import pandas as pd
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import classification_report, roc_auc_score
        from sklearn.model_selection import cross_val_score
    except ImportError:
        print("Install scikit-learn, pandas, numpy first:")
        print("  pip install scikit-learn pandas numpy")
        sys.exit(1)

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Load CSV
    # ------------------------------------------------------------------
    print(f"\nLoading {csv_path} ...")
    rows_raw: list[dict] = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows_raw.append(row)
    print(f"  {len(rows_raw):,} rows loaded")

    # Extract signals from each row
    print("Extracting language signals from text ...")
    signal_ids = list(LANGUAGE_SIGNALS.keys())
    matrix_rows: list[dict] = []

    for i, row in enumerate(rows_raw):
        if i % 1000 == 0:
            print(f"  [{i}/{len(rows_raw)}] ...")
        text  = row.get("text", "") or ""
        label = int(row.get("label", 0))
        ptype = row.get("phishing_type", "")

        body   = _text_to_body_signals(text)
        fired  = {s.id for s in (
            check_urgency(body) +
            check_credentials(body) +
            check_financial(body) +
            check_generic_greeting(body) +
            check_fake_security_alert(body) +
            check_otp_request(body) +
            check_spelling_errors(body)
        )}

        entry: dict = {"label": label, "phishing_type": ptype}
        for sid in signal_ids:
            entry[sid] = 1 if sid in fired else 0
        matrix_rows.append(entry)

    df = pd.DataFrame(matrix_rows)

    # Write signal matrix
    matrix_path = out / "text_layer_signals.csv"
    df.to_csv(matrix_path, index=False)
    print(f"\nWritten: {matrix_path}")

    # Fire rates per class
    phish = df[df["label"] == 1]
    legit = df[df["label"] == 0]
    n_p, n_l = len(phish), len(legit)

    print(f"\nDataset  -  phishing: {n_p:,}   legit: {n_l:,}")

    fire_rate_rows = []
    for sid in signal_ids:
        fr_phish = phish[sid].mean() * 100
        fr_legit = legit[sid].mean() * 100
        ratio    = fr_phish / max(fr_legit, 0.01)  # discrimination ratio
        fire_rate_rows.append({
            "Signal":          sid,
            "Manual_Weight":   LANGUAGE_SIGNALS[sid],
            "Fire_Phishing%":  round(fr_phish, 1),
            "Fire_Legit%":     round(fr_legit, 1),
            "Ratio_P/L":       round(ratio, 1),
        })

    fr_df = pd.DataFrame(fire_rate_rows).sort_values("Ratio_P/L", ascending=False)

    print(f"\n  {'Signal':<25} {'Manual':>6}  {'Phish%':>7} {'Legit%':>7} {'P/L ratio':>10}")
    print("  " + "-" * 60)
    for _, r in fr_df.iterrows():
        print(
            f"  {r['Signal']:<25} {r['Manual_Weight']:>6}  "
            f"{r['Fire_Phishing%']:>6.1f}%  {r['Fire_Legit%']:>6.1f}%  "
            f"{r['Ratio_P/L']:>9.1f}x"
        )

    # Logistic Regression
    print("\n=== Logistic Regression ===")
    X = df[signal_ids].values.astype(float)
    y = df["label"].values

    if len(np.unique(y)) < 2:
        print("Only one class - cannot fit LR.")
        return

    lr = LogisticRegression(class_weight="balanced", max_iter=1000, C=1.0, solver="lbfgs")
    lr.fit(X, y)
    coefs = lr.coef_[0]

    # Cross-validated AUC
    cv_auc = cross_val_score(lr, X, y, cv=5, scoring="roc_auc").mean()
    print(f"  5-fold CV AUC: {cv_auc:.3f}")

    # Normalize positive coefficients to 0-40 scale matching manual weights
    pos_coefs = np.clip(coefs, 0, None)
    coef_max  = pos_coefs.max() if pos_coefs.max() > 0 else 1.0
    lr_weights = (pos_coefs / coef_max * 40).round(1)

    # Build calibration table
    cal_rows = []
    for i, sid in enumerate(signal_ids):
        manual_w = LANGUAGE_SIGNALS[sid]
        lr_w     = float(lr_weights[i])
        delta    = lr_w - manual_w
        cal_rows.append({
            "Signal":          sid,
            "Manual_Weight":   manual_w,
            "LR_Coefficient":  round(float(coefs[i]), 4),
            "LR_Weight_0to40": round(lr_w, 1),
            "Delta":           round(delta, 1),
            "Fire_Phishing%":  round(float(phish[sid].mean() * 100), 1),
            "Fire_Legit%":     round(float(legit[sid].mean() * 100), 1),
            "P/L_Ratio":       round(float(phish[sid].mean() / max(legit[sid].mean(), 0.0001)), 1),
        })

    cal_df = pd.DataFrame(cal_rows).sort_values("Delta", key=abs, ascending=False)
    cal_path = out / "text_layer_calibration.csv"
    cal_df.to_csv(cal_path, index=False)
    print(f"  Written: {cal_path}")

    # Print calibration table
    print(f"\n  {'Signal':<25} {'Manual':>6} {'LR_0-40':>7} {'Delta':>7}  {'Phish%':>6} {'Legit%':>6}")
    print("  " + "-" * 70)
    for _, r in cal_df.iterrows():
        flag = (
            "  <-- OVER-calibrated"  if r["Delta"] < -5 else
            "  <-- UNDER-calibrated" if r["Delta"] > 5  else ""
        )
        print(
            f"  {r['Signal']:<25} {r['Manual_Weight']:>6} {r['LR_Weight_0to40']:>7} "
            f"{r['Delta']:>+7.1f}  {r['Fire_Phishing%']:>5.1f}% {r['Fire_Legit%']:>5.1f}%"
            f"{flag}"
        )

    # Per phishing_type breakdown - shows which signals work for each attack
    print("\n=== Signal fire rate by phishing subtype ===")
    subtypes = phish["phishing_type"].unique()
    print(f"  {'Subtype':<30}", end="")
    for sid in signal_ids:
        short = sid.replace("_", "")[:8]
        print(f" {short:>8}", end="")
    print()
    print("  " + "-" * (30 + 9 * len(signal_ids)))
    for st in sorted(subtypes):
        sub_df = phish[phish["phishing_type"] == st]
        print(f"  {st:<30}", end="")
        for sid in signal_ids:
            rate = sub_df[sid].mean() * 100
            print(f" {rate:>7.0f}%", end="")
        print()

    # Written recommendations
    lines = [
        "=== Text Layer Weight Calibration Report ===",
        "",
        f"Dataset: {csv_path}",
        f"Phishing samples: {n_p}  |  Legit samples: {n_l}",
        f"5-fold CV AUC: {cv_auc:.3f}",
        "",
        "RECOMMENDED WEIGHT UPDATES (LR-derived, validated against this dataset):",
        "",
    ]
    for _, r in cal_df.iterrows():
        delta = r["Delta"]
        action = "keep" if abs(delta) <= 3 else ("increase" if delta > 0 else "decrease")
        new_w  = int(round(r["LR_Weight_0to40"]))
        lines.append(
            f"  {r['Signal']:<25}  current={r['Manual_Weight']:>2}  "
            f"suggested={new_w:>2}  ({action})"
            f"  [fires on {r['Fire_Phishing%']}% phishing, {r['Fire_Legit%']}% legit]"
        )

    lines += [
        "",
        "NOTE: Signals with LR_Coefficient < 0 are slightly anti-correlated with",
        "phishing in this dataset. Do NOT set their weight to 0 - they may still",
        "be meaningful in real email that isn't captured here.",
        "",
        "NEXT STEPS:",
        "  1. Apply the suggested weights to backend/services/signals.py",
        "  2. Re-run this script to verify the AUC did not drop.",
        "  3. Run the URL layer calibration (tools/url_layer_calibration.py) next.",
    ]

    report = "\n".join(lines)
    print("\n" + report)
    report_path = out / "text_layer_report.txt"
    report_path.write_text(report + "\n", encoding="utf-8")
    print(f"\nWritten: {report_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Calibrate language_risk signal weights from labeled email text.",
    )
    parser.add_argument(
        "--csv", default="data/phishing_legit_dataset_KD_10000.csv",
        help="Path to CSV with columns: text, label, phishing_type, severity, confidence",
    )
    parser.add_argument(
        "--output", default="data/calibration_output",
        help="Output directory for calibration files",
    )
    args = parser.parse_args()
    run(args.csv, args.output)


if __name__ == "__main__":
    main()

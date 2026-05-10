# -*- coding: utf-8 -*-
"""
URL Layer Calibration
=====================

Calibrates the link_safety and spoofing_risk signal weights using a labeled
URL dataset (Dataset.csv from Kaggle or similar source).

Expected CSV columns (at minimum):
    url, dom, tld, is_ip, label
    (entropy, url_len, dash_cnt, slash_cnt, digit_ratio, query_len are used
     for bonus feature-importance analysis if present)

OUTPUTS
-------
  <output>/url_layer_signals.csv      -- Binary signal matrix per URL
  <output>/url_layer_calibration.csv  -- LR weights vs manual weights
  <output>/url_layer_report.txt       -- Summary + new signal recommendations

USAGE
-----
    python tools/url_layer_calibration.py \\
        --csv     Dataset.csv \\
        --output  data/calibration_output \\
        --sample  16600
"""
from __future__ import annotations

import argparse
import csv
import random
import re
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
_BACKEND = _ROOT / "backend"
for _p in [str(_ROOT), str(_BACKEND)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from backend.models.request import SenderInfo, UrlEntry
from backend.services.signals import (
    check_ip_urls, check_link_mismatch, check_shorteners,
    check_punycode_domains, check_suspicious_tld,
)


URL_SIGNALS: dict[str, int] = {
    "IP_URL":               20,
    "URL_SHORTENER":        22,
    "PUNYCODE_DOMAIN":      35,
    "SUSPICIOUS_TLD":       15,
    "LINK_MISMATCH":        10,
    "URL_COMPLEXITY_RISK":   0,
}

_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl",
    "short.link", "rb.gy", "is.gd", "buff.ly", "t.ly",
    "cutt.ly", "shorturl.at", "tiny.cc",
}

_HIGH_RISK_TLDS_LIVE = {
    ".top", ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".lol", ".bond", ".sbs", ".icu", ".support", ".click",
    ".zip", ".mov",
}

# TLDs seen frequently in phishing data but NOT yet in our live set
_CANDIDATE_TLDS: dict[str, int] = {}


def _is_ip_url(url: str) -> bool:
    return bool(re.match(r"https?://\d{1,3}(?:\.\d{1,3}){3}(?:[:/]|$)", url))


def _extract_tld(tld_col: str) -> str:
    """Normalise TLD column value to '.tld' format."""
    t = tld_col.strip().lower()
    if not t.startswith("."):
        t = "." + t
    return t


def _is_punycode(domain: str) -> bool:
    return "xn--" in domain.lower()


def _detect_schema(row: dict) -> str:
    """Return 'v2' if this is dataset_with_all_features v2, else 'v1'."""
    return "v2" if "adv_domain_ngram_entropy" in row else "v1"


def _label_from_row(row: dict, schema: str) -> int | None:
    """Return 1 (malicious) / 0 (benign) / None (skip) for a row."""
    if schema == "v2":
        t = row.get("type", "").strip().lower()
        if t == "benign":
            return 0
        if t in ("phishing", "malware", "defacement"):
            return 1
        return None
    else:
        lbl = row.get("label", "").strip()
        if lbl == "0":
            return 0
        if lbl == "1":
            return 1
        return None


def _signals_for_row(row: dict, schema: str) -> set[str]:
    """Fire URL signals from CSV columns - handles both v1 and v2 schemas."""
    fired: set[str] = set()

    if schema == "v2":
        url = row.get("url", "")
        dom = row.get("domain", row.get("dom", "")).lower()

        # IP URL
        if _safe_int(row.get("having_ip_address", 0)) or _is_ip_url(url):
            fired.add("IP_URL")

        # Shortener - dataset has pre-computed flag
        if _safe_int(row.get("Shortining_Service", 0)):
            fired.add("URL_SHORTENER")

        # Suspicious TLD - dataset has two pre-computed flags; take either
        if _safe_int(row.get("phish_suspicious_tld", 0)) or _safe_int(row.get("enh_suspicious_tld", 0)):
            fired.add("SUSPICIOUS_TLD")

        # Punycode
        if _is_punycode(dom):
            fired.add("PUNYCODE_DOMAIN")

        # URL_COMPLEXITY_RISK - uses pre-computed advanced features
        domain_entropy  = _safe_float(row.get("adv_domain_ngram_entropy", 0))
        digit_count     = _safe_float(row.get("phish_digit_count", 0))
        hyphen_count    = _safe_float(row.get("phish_hyphen_count", 0))
        url_len         = _safe_float(row.get("url_len", 0))
        score = 0
        if domain_entropy > 1.5:   score += 1   # random-looking domain name
        if digit_count     >= 3:   score += 1   # many digits in domain
        if hyphen_count    >= 2:   score += 1   # paypal-secure-login style
        if url_len         > 100:  score += 1   # unusually long URL
        if score >= 2:
            fired.add("URL_COMPLEXITY_RISK")

        # Candidate TLD tracking
        tld_raw = url.rsplit(".", 1)[-1].split("/")[0].split("?")[0].lower()
        tld = f".{tld_raw}" if tld_raw else ""
        if row.get("type", "") == "phishing" and tld not in _HIGH_RISK_TLDS_LIVE:
            _CANDIDATE_TLDS[tld] = _CANDIDATE_TLDS.get(tld, 0) + 1

    else:
        # v1 schema (original Dataset.csv)
        url    = row.get("url", "")
        dom    = row.get("dom", "").lower()
        tld    = _extract_tld(row.get("tld", ""))
        is_ip  = row.get("is_ip", "0") == "1"

        if is_ip or _is_ip_url(url):
            fired.add("IP_URL")
        if dom in _SHORTENER_DOMAINS:
            fired.add("URL_SHORTENER")
        if _is_punycode(dom):
            fired.add("PUNYCODE_DOMAIN")
        if tld in _HIGH_RISK_TLDS_LIVE:
            fired.add("SUSPICIOUS_TLD")
        if row.get("label", "0") == "1" and tld not in _HIGH_RISK_TLDS_LIVE:
            _CANDIDATE_TLDS[tld] = _CANDIDATE_TLDS.get(tld, 0) + 1

    return fired


def _safe_int(v) -> int:
    try:
        return int(float(v))
    except (ValueError, TypeError):
        return 0


def _safe_float(v) -> float:
    try:
        return float(v)
    except (ValueError, TypeError):
        return 0.0



def run(csv_path: str, output_dir: str, sample: int, seed: int) -> None:
    try:
        import numpy as np
        import pandas as pd
        from sklearn.linear_model import LogisticRegression
        from sklearn.model_selection import cross_val_score
    except ImportError:
        print("Install scikit-learn, pandas, numpy first:")
        print("  pip install scikit-learn pandas numpy")
        sys.exit(1)

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)

    # Load and balance dataset
    print(f"\nLoading {csv_path} ...")
    legit_rows, phish_rows = [], []
    schema = "v1"
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if schema == "v1" and "adv_domain_ngram_entropy" in row:
                schema = "v2"
            lbl = _label_from_row(row, schema)
            if lbl == 0:
                legit_rows.append(row)
            elif lbl == 1:
                phish_rows.append(row)

    rng.shuffle(legit_rows)
    rng.shuffle(phish_rows)
    n = min(sample, len(legit_rows), len(phish_rows))
    rows = legit_rows[:n] + phish_rows[:n]
    rng.shuffle(rows)

    print(f"  Schema: {schema}")
    print(f"  Loaded  legit: {len(legit_rows):,}   malicious: {len(phish_rows):,}")
    print(f"  Sampled {n:,} per class  ({2*n:,} total, balanced)")

    # Build signal matrix
    print("Extracting URL signals ...")
    signal_ids   = list(URL_SIGNALS.keys())
    matrix_rows: list[dict] = []

    for i, row in enumerate(rows):
        if i % 5000 == 0:
            print(f"  [{i}/{len(rows)}] ...")
        fired = _signals_for_row(row, schema)
        entry: dict = {"label": _label_from_row(row, schema) or 0}

        # Numeric features for bonus analysis (present in Kaggle dataset)
        for feat in ("entropy", "url_len", "dash_cnt", "slash_cnt",
                     "digit_ratio", "query_len", "subdom_cnt"):
            if feat in row:
                try:
                    entry[f"_feat_{feat}"] = float(row[feat])
                except ValueError:
                    entry[f"_feat_{feat}"] = 0.0

        for sid in signal_ids:
            entry[sid] = 1 if sid in fired else 0
        matrix_rows.append(entry)

    df = pd.DataFrame(matrix_rows)

    # Write signal matrix
    matrix_path = out / "url_layer_signals.csv"
    df[["label"] + signal_ids].to_csv(matrix_path, index=False)
    print(f"\nWritten: {matrix_path}")

    # Fire rates per class
    phish = df[df["label"] == 1]
    legit = df[df["label"] == 0]
    n_p, n_l = len(phish), len(legit)

    print(f"\nDataset  -  phishing: {n_p:,}   legit: {n_l:,}")
    print(f"\n  {'Signal':<20} {'Manual':>6}  {'Phish%':>7} {'Legit%':>7} {'P/L ratio':>10}")
    print("  " + "-" * 58)

    fire_rate_rows = []
    for sid in signal_ids:
        fp = phish[sid].mean() * 100
        fl = legit[sid].mean() * 100
        ratio = fp / max(fl, 0.01)
        fire_rate_rows.append({
            "Signal": sid, "Manual_Weight": URL_SIGNALS[sid],
            "Fire_Phishing%": round(fp, 1), "Fire_Legit%": round(fl, 1),
            "Ratio_P/L": round(ratio, 1),
        })
        print(
            f"  {sid:<20} {URL_SIGNALS[sid]:>6}  "
            f"{fp:>6.1f}%  {fl:>6.1f}%  {ratio:>9.1f}x"
        )

    # Logistic Regression on binary signals
    print("\n=== Logistic Regression (binary signals) ===")
    X_bin = df[signal_ids].values.astype(float)
    y     = df["label"].values

    fired_count = X_bin.sum(axis=1)
    never_fired = (fired_count == 0).sum()
    print(f"  URLs where NO signal fired: {never_fired:,} / {len(rows):,} "
          f"({100*never_fired/len(rows):.0f}%) - these rely on expert weights")

    lr_bin = LogisticRegression(class_weight="balanced", max_iter=1000, C=1.0)
    lr_bin.fit(X_bin, y)
    coefs_bin  = lr_bin.coef_[0]
    auc_bin    = cross_val_score(lr_bin, X_bin, y, cv=5, scoring="roc_auc").mean()
    print(f"  5-fold CV AUC (binary signals only): {auc_bin:.3f}")

    pos_coefs = __import__("numpy").clip(coefs_bin, 0, None)
    coef_max  = pos_coefs.max() if pos_coefs.max() > 0 else 1.0
    lr_weights = (pos_coefs / coef_max * 40).round(1)

    cal_rows = []
    for i, sid in enumerate(signal_ids):
        manual_w = URL_SIGNALS[sid]
        lr_w     = float(lr_weights[i])
        delta    = lr_w - manual_w
        cal_rows.append({
            "Signal":          sid,
            "Manual_Weight":   manual_w,
            "LR_Coefficient":  round(float(coefs_bin[i]), 4),
            "LR_Weight_0to40": round(lr_w, 1),
            "Delta":           round(delta, 1),
            "Fire_Phishing%":  round(float(phish[sid].mean() * 100), 1),
            "Fire_Legit%":     round(float(legit[sid].mean() * 100), 1),
        })

    cal_df   = pd.DataFrame(cal_rows).sort_values("Delta", key=abs, ascending=False)
    cal_path = out / "url_layer_calibration.csv"
    cal_df.to_csv(cal_path, index=False)
    print(f"  Written: {cal_path}")

    print(f"\n  {'Signal':<20} {'Manual':>6} {'LR_0-40':>7} {'Delta':>7}  {'Phish%':>6} {'Legit%':>6}")
    print("  " + "-" * 65)
    for _, r in cal_df.iterrows():
        flag = (
            "  <-- OVER-calibrated"  if r["Delta"] < -5 else
            "  <-- UNDER-calibrated" if r["Delta"] > 5  else ""
        )
        print(
            f"  {r['Signal']:<20} {r['Manual_Weight']:>6} {r['LR_Weight_0to40']:>7} "
            f"{r['Delta']:>+7.1f}  {r['Fire_Phishing%']:>5.1f}% {r['Fire_Legit%']:>5.1f}%"
            f"{flag}"
        )

    # BONUS: numeric feature importance (reveals new signal candidates)
    feat_cols = [c for c in df.columns if c.startswith("_feat_")]
    if feat_cols:
        print("\n=== Bonus: numeric feature importance ===")
        print("  (These features are NOT yet used as signals - LR tells us if they should be)\n")
        X_feat = df[feat_cols].fillna(0).values.astype(float)
        lr_feat = LogisticRegression(class_weight="balanced", max_iter=1000, C=0.5)
        lr_feat.fit(X_feat, y)
        auc_feat = cross_val_score(lr_feat, X_feat, y, cv=5, scoring="roc_auc").mean()
        print(f"  5-fold CV AUC (numeric features): {auc_feat:.3f}")

        feat_importance = sorted(
            zip([c.replace("_feat_", "") for c in feat_cols], lr_feat.coef_[0]),
            key=lambda x: abs(x[1]), reverse=True,
        )
        print(f"\n  {'Feature':<20} {'LR coef':>10}  Interpretation")
        print("  " + "-" * 65)
        for feat, coef in feat_importance:
            direction = "higher = more phishing" if coef > 0 else "lower  = more phishing"
            flag = "  *** STRONG signal candidate" if abs(coef) > 0.5 else ""
            print(f"  {feat:<20} {coef:>+10.4f}  {direction}{flag}")

    # Candidate TLD analysis
    top_candidate_tlds = sorted(
        [(tld, cnt) for tld, cnt in _CANDIDATE_TLDS.items() if cnt >= 10],
        key=lambda x: -x[1],
    )[:20]

    if top_candidate_tlds:
        print("\n=== TLDs in phishing data NOT covered by _HIGH_RISK_TLDS ===")
        print("  (Consider adding the top ones to expand SUSPICIOUS_TLD coverage)\n")
        print(f"  {'TLD':<15} {'Phishing URLs':>14}")
        print("  " + "-" * 32)
        for tld, cnt in top_candidate_tlds:
            print(f"  {tld:<15} {cnt:>14,}")

    # Written report
    lines = [
        "=== URL Layer Weight Calibration Report ===",
        "",
        f"Dataset: {csv_path}",
        f"Phishing URLs: {n_p:,}  |  Legit URLs: {n_l:,}",
        f"5-fold CV AUC (binary signals): {auc_bin:.3f}",
        "",
        "RECOMMENDED WEIGHT UPDATES:",
        "",
    ]
    for _, r in cal_df.iterrows():
        delta  = r["Delta"]
        action = "keep" if abs(delta) <= 3 else ("increase" if delta > 0 else "decrease")
        new_w  = int(round(r["LR_Weight_0to40"]))
        lines.append(
            f"  {r['Signal']:<20}  current={r['Manual_Weight']:>2}  "
            f"suggested={new_w:>2}  ({action})"
            f"  [fires: {r['Fire_Phishing%']}% phish / {r['Fire_Legit%']}% legit]"
        )

    if top_candidate_tlds:
        lines += ["", "TLD EXPANSION - add to _HIGH_RISK_TLDS in signals.py:"]
        for tld, cnt in top_candidate_tlds[:10]:
            lines.append(f"  \"{tld[1:]}\"  ({cnt:,} phishing URLs in dataset)")

    lines += [
        "",
        "NOTE: LINK_MISMATCH cannot be evaluated from URL alone (needs",
        "display text vs href). Keep its current weight (expert judgment).",
        "",
        "NEXT STEPS:",
        "  1. Apply suggested weight changes to backend/services/signals.py",
        "  2. Consider adding top candidate TLDs to _HIGH_RISK_TLDS",
        "  3. If numeric features show strong candidates, consider new signals",
    ]

    report = "\n".join(lines)
    print("\n" + report)
    report_path = out / "url_layer_report.txt"
    report_path.write_text(report + "\n", encoding="utf-8")
    print(f"\nWritten: {report_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Calibrate link_safety/spoofing_risk signal weights from a labeled URL dataset.",
    )
    parser.add_argument("--csv",    default="Dataset.csv",
                        help="Path to labeled URL CSV (default: Dataset.csv)")
    parser.add_argument("--output", default="data/calibration_output")
    parser.add_argument("--sample", type=int, default=16600,
                        help="URLs to sample per class for balance (default: 16600 = all phishing)")
    parser.add_argument("--seed",   type=int, default=42)
    args = parser.parse_args()
    run(args.csv, args.output, args.sample, args.seed)


if __name__ == "__main__":
    main()

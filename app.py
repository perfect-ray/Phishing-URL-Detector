"""
PhishGuard — Phishing URL Scanner
Flask web app that scores a URL as legitimate or phishing using a
RandomForest model trained on the PhiUSIIL Phishing URL dataset.
"""

import os
from concurrent.futures import ThreadPoolExecutor

import joblib
import numpy as np
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

from feature_extractor import FEATURE_NAMES, extract_features_detail
from enrichment import get_virustotal_report, get_whois_info, get_dns_info
from holistic import compute_holistic

load_dotenv()

APP_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(APP_DIR, "model", "phishing_model.pkl")
VIRUSTOTAL_API_KEY = "XXXXXXXXX"

app = Flask(__name__)

_bundle = joblib.load(MODEL_PATH)
MODEL = _bundle["model"]
TRAIN_ACCURACY = _bundle.get("accuracy")
TRAIN_AUC = _bundle.get("roc_auc")

# Human-readable descriptions for the signal breakdown panel shown in the UI
SIGNAL_DEFS = [
    ("IsHTTPS", "Uses HTTPS", lambda v: "Yes" if v else "No", lambda v: v == 0),
    ("IsDomainIP", "Domain is a raw IP address", lambda v: "Yes" if v else "No", lambda v: v == 1),
    ("HasAtSymbol", "Contains '@' symbol", lambda v: "Yes" if v else "No", lambda v: v == 1),
    ("HasObfuscation", "Contains %-encoded characters", lambda v: "Yes" if v else "No", lambda v: v == 1),
    ("IsShortenedURL", "Uses a known URL shortener", lambda v: "Yes" if v else "No", lambda v: v == 1),
    ("HasSuspiciousWords", "Contains suspicious keywords", lambda v: "Yes" if v else "No", lambda v: v == 1),
    ("NoOfSubDomain", "Number of subdomains", lambda v: str(v), lambda v: v >= 3),
    ("URLLength", "URL length (characters)", lambda v: str(v), lambda v: v >= 75),
    ("HasPort", "Explicit port in URL", lambda v: "Yes" if v else "No", lambda v: v == 1),
    ("IsTyposquatSuspected", "Looks like a brand lookalike (typosquat)", lambda v: "Yes" if v else "No", lambda v: v == 1),
]


def build_signal_breakdown(feats: dict):
    signals = []
    for key, label, fmt, is_risky in SIGNAL_DEFS:
        value = feats[key]
        signals.append(
            {
                "label": label,
                "value": fmt(value),
                "risky": bool(is_risky(value)),
            }
        )
    return signals


def predict_url(url: str):
    feats = extract_features_detail(url)
    vector = np.array([[feats[name] for name in FEATURE_NAMES]], dtype=float)
    proba_legit = float(MODEL.predict_proba(vector)[0][1])
    proba_phish = 1.0 - proba_legit

    # Safety net: typosquatting a well-known brand (e.g. "g00gle.com",
    # "paypa1.com") is a near-certain phishing signal, but it's rare in the
    # training data, so the ML model alone sometimes under-weights it. Floor
    # the phishing probability rather than relying purely on the learned
    # weight for this specific, high-precision rule.
    if feats.get("IsTyposquatSuspected") and not feats.get("IsBrandExactMatch"):
        proba_phish = max(proba_phish, 0.93)
        proba_legit = 1.0 - proba_phish

    label = "legitimate" if proba_legit >= 0.5 else "phishing"

    return {
        "url": url,
        "label": label,
        "probability_legitimate": round(proba_legit * 100, 2),
        "probability_phishing": round(proba_phish * 100, 2),
        "domain": feats["_domain"],
        "tld": feats["_tld"],
        "matched_suspicious_words": feats["_matched_suspicious_words"],
        "signals": build_signal_breakdown(feats),
    }


@app.route("/")
def index():
    return render_template(
        "index.html",
        accuracy=round((TRAIN_ACCURACY or 0) * 100, 2),
        auc=round((TRAIN_AUC or 0) * 100, 2),
        vt_configured=bool(VIRUSTOTAL_API_KEY),
    )


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Please provide a URL to scan."}), 400
    if len(url) > 2048:
        return jsonify({"error": "URL is too long."}), 400

    try:
        result = predict_url(url)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"Could not analyze URL: {exc}"}), 400

    return jsonify(result)


@app.route("/api/enrich", methods=["POST"])
def api_enrich():
    """VirusTotal + WHOIS + DNS, run alongside (not inside) the ML scan.

    Kept as a separate endpoint so the fast ML verdict from /api/scan is
    never delayed by these slower, third-party lookups. Model logic is
    untouched -- this is purely additional context for the UI.
    """
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Please provide a URL to scan."}), 400
    if len(url) > 2048:
        return jsonify({"error": "URL is too long."}), 400

    try:
        feats = extract_features_detail(url)
        ml_result = predict_url(url)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"Could not analyze URL: {exc}"}), 400

    domain = feats["_domain"]

    with ThreadPoolExecutor(max_workers=3) as ex:
        vt_future = ex.submit(get_virustotal_report, url, VIRUSTOTAL_API_KEY)
        whois_future = ex.submit(get_whois_info, domain)
        dns_future = ex.submit(get_dns_info, domain)
        virustotal = vt_future.result()
        whois_info = whois_future.result()
        dns_info = dns_future.result()

    holistic = compute_holistic(
        ml_proba_phish=ml_result["probability_phishing"] / 100.0,
        typosquat_suspected=bool(feats.get("IsTyposquatSuspected")) and not bool(feats.get("IsBrandExactMatch")),
        vt_info=virustotal,
        whois_info=whois_info,
        dns_info=dns_info,
    )

    return jsonify(
        {
            "url": url,
            "domain": domain,
            "ml": ml_result,
            "virustotal": virustotal,
            "whois": whois_info,
            "dns": dns_info,
            "holistic": holistic,
        }
    )


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)

"""
holistic.py

Combines the ML verdict with VirusTotal, WHOIS, and DNS into one transparent
"holistic" risk score. This is a presentation/aggregation layer only -- it
does not change the RandomForest model, its features, or its training in
any way. It runs downstream of predict_url() and the enrichment lookups,
blending their outputs.

Design:
- Each source contributes a risk value in [0, 1] (0 = looks fine, 1 = looks
  bad) plus a base weight. A source that's unavailable (no API key, lookup
  failed, no data) is simply excluded and the remaining weights are
  renormalized -- we never guess a neutral value for missing data.
- On top of the weighted blend, two hard "escalate only" overrides can push
  the score up (never down): a VirusTotal multi-engine malicious consensus,
  or a suspected brand typosquat. We only ever override toward *more*
  suspicious, never toward "trust it" -- if the sources disagree, that's
  worth surfacing, not smoothing over.
"""

BASE_WEIGHTS = {
    "ml": 0.55,
    "virustotal": 0.30,
    "whois": 0.10,
    "dns": 0.05,
}


def _whois_risk(whois_info: dict):
    if not whois_info or not whois_info.get("available"):
        return None
    age = whois_info.get("domain_age_days")
    if age is None:
        return None
    if age < 7:
        return 0.95
    if age < 30:
        return 0.80
    if age < 90:
        return 0.55
    if age < 365:
        return 0.30
    if age < 365 * 3:
        return 0.15
    return 0.05


def _dns_risk(dns_info: dict):
    if not dns_info or not dns_info.get("available"):
        return None
    return 0.10 if dns_info.get("resolves") else 0.65


def _vt_risk(vt_info: dict):
    if not vt_info or not vt_info.get("available") or vt_info.get("status") != "completed":
        return None
    total = vt_info.get("total_engines") or 0
    if total == 0:
        return None
    flagged = vt_info.get("flagged") or 0
    return min(1.0, flagged / total)


def compute_holistic(ml_proba_phish: float, typosquat_suspected: bool, vt_info: dict, whois_info: dict, dns_info: dict):
    sources = {
        "ml": ml_proba_phish,
        "virustotal": _vt_risk(vt_info),
        "whois": _whois_risk(whois_info),
        "dns": _dns_risk(dns_info),
    }

    available = {k: v for k, v in sources.items() if v is not None}
    total_weight = sum(BASE_WEIGHTS[k] for k in available)
    breakdown = []
    weighted_sum = 0.0

    for key, risk in sources.items():
        used = key in available
        weight = (BASE_WEIGHTS[key] / total_weight) if used and total_weight > 0 else 0.0
        if used:
            weighted_sum += weight * risk
        breakdown.append({
            "source": key,
            "available": used,
            "risk": round(risk, 3) if used else None,
            "weight": round(weight, 3),
        })

    score = weighted_sum if total_weight > 0 else ml_proba_phish
    overrides = []

    vt_malicious = (vt_info or {}).get("malicious") or 0
    if vt_malicious >= 3:
        score = max(score, 0.95)
        overrides.append(f"VirusTotal: {vt_malicious} security vendors flagged this URL as malicious")

    if typosquat_suspected:
        score = max(score, 0.90)
        overrides.append("URL closely resembles a well-known brand name (suspected typosquat)")

    score = max(0.0, min(1.0, score))
    label = "phishing" if score >= 0.5 else "legitimate"

    return {
        "score": round(score * 100, 2),
        "label": label,
        "confidence": round((score if label == "phishing" else 1 - score) * 100, 2),
        "breakdown": breakdown,
        "overrides": overrides,
        "sources_used": list(available.keys()),
    }

"""
enrichment.py

Optional, independent enrichment sources shown alongside the ML verdict:
VirusTotal (multi-engine scan), WHOIS (domain registration), and DNS
resolution. None of this feeds back into the ML model -- it's purely
additional context rendered next to it, so the model's logic/features stay
exactly as trained.

Every function fails soft: on any error (missing API key, network issue,
rate limit, WHOIS/DNS lookup failure) it returns a dict with
`"available": False` and a `"reason"` instead of raising, so one broken
source never breaks the whole scan.
"""

import base64
import time
from datetime import datetime, timezone

import requests

try:
    import whois as whois_lib
except ImportError:  # pragma: no cover
    whois_lib = None

try:
    import dns.resolver
except ImportError:  # pragma: no cover
    dns = None

VT_BASE = "https://www.virustotal.com/api/v3"
DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT"]


# ---------------------------------------------------------------- VirusTotal

def _vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def _format_vt_stats(attrs: dict, url_id: str, status: str) -> dict:
    stats = attrs.get("last_analysis_stats") or attrs.get("stats") or {}
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected

    last_date = attrs.get("last_analysis_date") or attrs.get("date")
    last_analysis_iso = None
    if isinstance(last_date, (int, float)):
        last_analysis_iso = datetime.fromtimestamp(last_date, tz=timezone.utc).isoformat()

    return {
        "available": True,
        "status": status,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total_engines": total,
        "flagged": malicious + suspicious,
        "reputation": attrs.get("reputation"),
        "categories": attrs.get("categories") or {},
        "last_analysis_date": last_analysis_iso,
        "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
    }


def get_virustotal_report(url: str, api_key: str, max_poll: int = 4, poll_interval: int = 3) -> dict:
    """Look up (or, if unseen, submit + poll for) a VirusTotal URL report."""
    if not api_key:
        return {"available": False, "reason": "no_api_key"}

    headers = {"x-apikey": api_key}
    url_id = _vt_url_id(url)

    try:
        r = requests.get(f"{VT_BASE}/urls/{url_id}", headers=headers, timeout=10)
    except requests.RequestException as exc:
        return {"available": False, "reason": "network_error", "detail": str(exc)}

    if r.status_code == 200:
        attrs = r.json()["data"]["attributes"]
        return _format_vt_stats(attrs, url_id, status="completed")

    if r.status_code == 401:
        return {"available": False, "reason": "invalid_api_key"}

    if r.status_code == 429:
        return {"available": False, "reason": "rate_limited"}

    if r.status_code != 404:
        return {"available": False, "reason": "http_error", "detail": f"HTTP {r.status_code}"}

    # 404: VirusTotal has never scanned this exact URL -- submit it.
    try:
        sub = requests.post(f"{VT_BASE}/urls", headers=headers, data={"url": url}, timeout=10)
        sub.raise_for_status()
    except requests.RequestException as exc:
        return {"available": False, "reason": "submit_failed", "detail": str(exc)}

    analysis_id = sub.json()["data"]["id"]

    for _ in range(max_poll):
        time.sleep(poll_interval)
        try:
            a = requests.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers, timeout=10)
            a.raise_for_status()
        except requests.RequestException:
            continue
        attrs = a.json()["data"]["attributes"]
        if attrs.get("status") == "completed":
            return _format_vt_stats(attrs, url_id, status="completed")

    return {
        "available": True,
        "status": "pending",
        "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
        "message": "First-time scan -- VirusTotal is still analyzing this URL.",
    }


# --------------------------------------------------------------------- WHOIS

def _first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _to_naive(dt):
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def get_whois_info(domain: str) -> dict:
    if whois_lib is None:
        return {"available": False, "reason": "library_missing"}
    if not domain:
        return {"available": False, "reason": "no_domain"}

    try:
        w = whois_lib.whois(domain)
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": "lookup_failed", "detail": str(exc)}

    if not w or not (w.domain_name or w.creation_date):
        return {"available": False, "reason": "no_data"}

    creation = _to_naive(_first(w.creation_date))
    expiration = _to_naive(_first(w.expiration_date))
    updated = _to_naive(_first(w.updated_date))

    age_days = None
    if creation:
        try:
            age_days = (datetime.utcnow() - creation).days
        except Exception:  # noqa: BLE001
            age_days = None

    name_servers = w.name_servers
    if isinstance(name_servers, (list, set)):
        name_servers = sorted({str(ns).lower() for ns in name_servers})
    elif name_servers:
        name_servers = [str(name_servers).lower()]
    else:
        name_servers = []

    status = w.status
    if isinstance(status, str):
        status = [status]
    elif not status:
        status = []

    return {
        "available": True,
        "registrar": w.registrar,
        "creation_date": creation.isoformat() if creation else None,
        "expiration_date": expiration.isoformat() if expiration else None,
        "updated_date": updated.isoformat() if updated else None,
        "domain_age_days": age_days,
        "name_servers": name_servers,
        "status": status,
        "org": getattr(w, "org", None),
        "country": getattr(w, "country", None),
    }


# ----------------------------------------------------------------------- DNS

def get_dns_info(domain: str) -> dict:
    if dns is None:
        return {"available": False, "reason": "library_missing"}
    if not domain:
        return {"available": False, "reason": "no_domain"}

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    records = {}
    resolved_any = False
    for rtype in DNS_RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            values = [str(a).rstrip(".") for a in answers]
            records[rtype] = values
            if values:
                resolved_any = True
        except Exception:  # noqa: BLE001
            records[rtype] = []

    return {
        "available": True,
        "resolves": resolved_any,
        "records": records,
    }

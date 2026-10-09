"""
feature_extractor.py

Turns a raw URL string into a fixed vector of lexical/structural features.

IMPORTANT: this exact function is used both to build the training matrix
(from the PhiUSIIL dataset's URL column) and at inference time in the Flask
app. Only features computable from the URL string itself are used (no page
crawling), so the web app can score any URL instantly and offline.
"""

import re
import math
from urllib.parse import urlparse

import tldextract

# Public-suffix-aware domain parsing (so "bank.in", "co.uk", "com.au" etc.
# are treated as a single suffix, not "in"/"uk"/"au" with an extra fake
# subdomain). Uses tldextract's default behavior: try to fetch the latest
# public suffix list once, cache it on disk, and fall back to the snapshot
# bundled with the library if offline -- that bundled snapshot is what
# correctly resolves newer entries like "bank.in" in this project's testing.
# We warm the cache at import time so any first-fetch delay happens once at
# startup, not mid-request.
_TLD_EXTRACTOR = tldextract.TLDExtract()
_TLD_EXTRACTOR("warmup.example.com")

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "banking", "password", "billing", "webscr", "ebayisapi", "suspend",
    "authenticate", "wallet", "recover", "unlock",
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "cutt.ly", "rebrand.ly", "shorte.st",
}

IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# A short list of frequently-impersonated brand names (second-level domain,
# no TLD) used to detect typosquatting -- e.g. "g00gle" or "paypa1" that are
# visually close to a real brand but aren't the real domain. This is a
# generic character-similarity check, not a lookup of "the correct site";
# it flags visual deception, it doesn't verify authenticity.
BRAND_NAMES = [
    "google", "youtube", "gmail", "facebook", "instagram", "whatsapp",
    "amazon", "apple", "icloud", "microsoft", "outlook", "office365",
    "netflix", "paypal", "ebay", "linkedin", "twitter", "dropbox", "adobe",
    "coinbase", "binance", "chase", "wellsfargo", "bankofamerica", "citibank",
    "hsbc", "americanexpress", "usbank", "capitalone", "irs", "usps", "fedex",
    "dhl", "ups", "docusign", "spotify", "steam", "roblox", "epicgames",
    "playstation", "xbox", "twitch", "discord", "telegram", "yahoo",
    "wordpress", "shopify", "zoom", "att", "verizon", "tmobile",
]

_LEET_MAP = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s",
    "@": "a",
})


def _leet_normalize(s: str) -> str:
    s = s.lower().translate(_LEET_MAP)
    s = s.replace("vv", "w").replace("rn", "m")
    s = s.replace("-", "").replace("_", "")
    return s


def _levenshtein(a: str, b: str, max_dist: int = 4) -> int:
    """Bounded edit distance; returns max_dist+1 if the true distance exceeds it."""
    if abs(len(a) - len(b)) > max_dist:
        return max_dist + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        row_min = cur[0]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            row_min = min(row_min, cur[j])
        if row_min > max_dist:
            return max_dist + 1
        prev = cur
    return min(prev[-1], max_dist + 1)


def _brand_features(sld: str):
    """Detect typosquatting: an SLD (or a hyphen-separated piece of it) that's
    visually close to, or contains, a known brand name but the domain isn't
    the brand's real one. Returns (is_exact, is_typosquat, min_dist)."""
    raw = sld.lower()
    norm_whole = _leet_normalize(raw)

    if raw in BRAND_NAMES:
        return 1, 0, 0

    tokens = {raw, norm_whole} | {t for t in raw.split("-") if t}

    best_dist = 99
    for token in tokens:
        if len(token) < 3:
            continue
        token_norm = _leet_normalize(token)
        for brand in BRAND_NAMES:
            if token == brand and raw != brand:
                # brand name embedded verbatim in a larger/compound domain
                best_dist = 0
                break
            if abs(len(token_norm) - len(brand)) > 3:
                continue
            if token_norm == brand:
                best_dist = 0
                break
            # Short brand names (e.g. "att", "dhl", "ups") need near-exact
            # matches -- allowing edit distance 2 on 3-4 letter strings
            # makes almost any generic short word match something.
            allowed = 1 if len(brand) <= 4 else 2
            d = _levenshtein(token, brand, max_dist=allowed)
            if d <= allowed:
                best_dist = min(best_dist, d)
        if best_dist == 0:
            break

    is_typosquat = 1 if 0 <= best_dist <= 2 else 0
    return 0, is_typosquat, min(best_dist, 5)

FEATURE_NAMES = [
    "URLLength",
    "DomainLength",
    "TLDLength",
    "IsDomainIP",
    "NoOfSubDomain",
    "NoOfDots",
    "IsHTTPS",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfDashInURL",
    "NoOfUnderscoreInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "CharContinuationRate",
    "HasAtSymbol",
    "HasSuspiciousWords",
    "NoOfSuspiciousWords",
    "IsShortenedURL",
    "PathLength",
    "NoOfPathSegments",
    "HasPort",
    "IsBrandExactMatch",
    "IsTyposquatSuspected",
    "BrandEditDistance",
]


def _safe_domain(url: str):
    """Extract a netloc-like domain even if the URL is missing a scheme."""
    parsed = urlparse(url if "://" in url else "http://" + url)
    domain = parsed.netloc.split("@")[-1]  # strip user:pass@ if present
    domain = domain.split(":")[0]  # strip port
    return parsed, domain


def _char_continuation_rate(s: str) -> float:
    """Longest run of the identical character, as a fraction of length."""
    if not s:
        return 0.0
    max_run = 1
    run = 1
    for i in range(1, len(s)):
        if s[i] == s[i - 1]:
            run += 1
            max_run = max(max_run, run)
        else:
            run = 1
    return max_run / len(s)


def extract_features(url: str) -> dict:
    url = (url or "").strip()
    parsed, domain = _safe_domain(url)

    ext = _TLD_EXTRACTOR(domain) if domain else None
    sld = ext.domain if ext else ""
    suffix = ext.suffix if ext else ""
    subdomain_part = ext.subdomain if ext else ""
    tld = suffix.split(".")[-1] if suffix else ""
    no_of_subdomain = len([p for p in subdomain_part.split(".") if p]) if subdomain_part else 0

    is_domain_ip = 1 if IPV4_RE.match(domain) else 0

    is_https = 1 if parsed.scheme == "https" else 0

    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)
    url_len = len(url) if url else 1

    equals = url.count("=")
    qmarks = url.count("?")
    amps = url.count("&")
    dashes = url.count("-")
    underscores = url.count("_")

    allowed = set(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        "-._~:/?#[]@!$&'()*+,;=%"
    )
    other_special = sum(1 for c in url if not c.isalnum() and c not in ".-_/:")

    has_obfuscation = 1 if "%" in url else 0
    obf_chars = url.count("%")
    obf_ratio = obf_chars / url_len

    has_at = 1 if "@" in url else 0

    lower_url = url.lower()
    matched_words = [w for w in SUSPICIOUS_WORDS if w in lower_url]

    is_shortened = 1 if domain.lower() in SHORTENERS else 0

    path = parsed.path or ""
    path_segments = [p for p in path.split("/") if p]

    has_port = 1 if parsed.port else 0

    # second-level domain (via tldextract), used for typosquat check
    is_brand_exact, is_typosquat, brand_dist = _brand_features(sld)

    feats = {
        "URLLength": len(url),
        "DomainLength": len(domain),
        "TLDLength": len(tld),
        "IsDomainIP": is_domain_ip,
        "NoOfSubDomain": no_of_subdomain,
        "NoOfDots": url.count("."),
        "IsHTTPS": is_https,
        "NoOfLettersInURL": letters,
        "LetterRatioInURL": letters / url_len,
        "NoOfDegitsInURL": digits,
        "DegitRatioInURL": digits / url_len,
        "NoOfEqualsInURL": equals,
        "NoOfQMarkInURL": qmarks,
        "NoOfAmpersandInURL": amps,
        "NoOfDashInURL": dashes,
        "NoOfUnderscoreInURL": underscores,
        "NoOfOtherSpecialCharsInURL": other_special,
        "SpacialCharRatioInURL": other_special / url_len,
        "HasObfuscation": has_obfuscation,
        "NoOfObfuscatedChar": obf_chars,
        "ObfuscationRatio": obf_ratio,
        "CharContinuationRate": _char_continuation_rate(url),
        "HasAtSymbol": has_at,
        "HasSuspiciousWords": 1 if matched_words else 0,
        "NoOfSuspiciousWords": len(matched_words),
        "IsShortenedURL": is_shortened,
        "PathLength": len(path),
        "NoOfPathSegments": len(path_segments),
        "HasPort": has_port,
        "IsBrandExactMatch": is_brand_exact,
        "IsTyposquatSuspected": is_typosquat,
        "BrandEditDistance": brand_dist,
    }
    return feats


def extract_features_vector(url: str):
    feats = extract_features(url)
    return [feats[name] for name in FEATURE_NAMES]


def extract_features_detail(url: str):
    """Return features plus a few human-readable flags for the UI."""
    feats = extract_features(url)
    parsed, domain = _safe_domain(url)
    lower_url = (url or "").lower()
    matched_words = [w for w in SUSPICIOUS_WORDS if w in lower_url]
    feats["_domain"] = domain
    feats["_tld"] = domain.split(".")[-1] if "." in domain else ""
    feats["_matched_suspicious_words"] = matched_words
    feats["_scheme"] = parsed.scheme
    return feats

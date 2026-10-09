# PhishGuard — Phishing URL Detector

A Flask web app that scores any URL as **legitimate** or **phishing**, trained on the
[PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset)
(235,795 labeled URLs).

## How it works

The original PhiUSIIL dataset includes both URL-text features and features that require
crawling the live page (title, favicon, image count, etc.). This app trains **only on
features computable from the URL string itself** (length, structure, character
composition, encoding, subdomain count, HTTPS usage, suspicious keywords, and more —
see `feature_extractor.py`). That's what lets the web app score a pasted URL instantly,
without fetching the destination page.

**Dataset artifact fix:** raw PhiUSIIL has two quirks in its legitimate (label=1) URLs —
every single one is a bare `scheme://domain` with no path, and every single one starts
with `www.`. Trained naively, a model exploits those as shortcuts ("any path or missing
`www.` ⇒ phishing"), which fails on completely normal real-world URLs like
`google.com/search?q=...` or `github.com`. `train_model.py` corrects this by augmenting a
portion of the legitimate training URLs with realistic paths and by stripping `www.` from
another portion, before training — see `augment_legitimate_urls()`.

Model: a `RandomForestClassifier` (scikit-learn, 150 trees), reaching **~97.8% accuracy**
and **~99.4% ROC AUC** on a held-out 20% test split (slightly lower than a naive fit,
but that's the artifact being removed, not real predictive power being lost).

**Typosquat / brand-impersonation detection:** the ML model alone under-weights this
signal because it's rare in the training data, so `feature_extractor.py` includes an
explicit check against ~50 commonly-impersonated brand names (Google, PayPal, Amazon,
Microsoft, banks, etc.), catching things like `g00gle.com`, `paypa1-login.com`, or
`chase-account-verify.com` via character-substitution normalization and bounded edit
distance — including brand names embedded in a compound/hyphenated domain. When this
fires, `app.py` floors the phishing probability at 93% rather than relying purely on
the model's learned weight for it. It requires a fairly close match (not just "contains
a common word"), so short generic words don't collide with short brand codes.

## Project structure

```
phishing-detector/
├── app.py                  # Flask app (routes: /, /api/scan, /api/enrich)
├── feature_extractor.py    # URL -> feature vector, shared by training & serving
├── enrichment.py           # VirusTotal / WHOIS / DNS lookups (independent of the model)
├── holistic.py             # Combines ML + VT + WHOIS + DNS into one score (display-only)
├── train_model.py          # Trains the RandomForest on the PhiUSIIL CSV
├── requirements.txt
├── model/
│   └── phishing_model.pkl  # Trained model (already included)
├── templates/
│   └── index.html
└── static/
    ├── style.css
    └── app.js
```

**Typosquat / brand-impersonation detection:** the ML model alone under-weights this
signal because it's rare in the training data, so `feature_extractor.py` includes an
explicit check against ~50 commonly-impersonated brand names (Google, PayPal, Amazon,
Microsoft, banks, etc.), catching things like `g00gle.com`, `paypa1-login.com`, or
`chase-account-verify.com` via character-substitution normalization and bounded edit
distance — including brand names embedded in a compound/hyphenated domain. When this
fires, `app.py` floors the phishing probability at 93% rather than relying purely on
the model's learned weight for it. It requires a fairly close match (not just "contains
a common word"), so short generic words don't collide with short brand codes.

**Public-suffix-aware domain parsing:** domain/subdomain splitting uses `tldextract`
(with the Public Suffix List) instead of naive dot-splitting, so multi-part suffixes
like `.bank.in`, `.co.uk`, `.com.au` are handled correctly — e.g. `hdfc.bank.in`
correctly reads as domain `hdfc` under suffix `bank.in`, not domain `bank` under `.in`
(which used to misfire the subdomain count and the typosquat check).

## Holistic scoring: combining ML + VirusTotal + WHOIS + DNS

`holistic.py` blends all four sources into one score, shown as its own "holistic
verdict" panel. It's a downstream aggregation layer only — **the ML model's features,
training, and `/api/scan` output are untouched**; this just combines everything
afterward for display.

How it works:
- Each source (ML, VirusTotal, WHOIS, DNS) contributes a risk value in [0, 1] and a
  base weight (ML 55%, VirusTotal 30%, WHOIS 10%, DNS 5%). ML is weighted highest
  because it's always available and it's what the other three get checked against.
- WHOIS contributes via domain age (a domain registered days ago is a much stronger
  red flag than one that's been around for years); DNS contributes via whether the
  domain resolves at all.
- **A source that's unavailable is excluded, not defaulted to neutral** — if you have
  no VirusTotal key, the weight is redistributed across ML/WHOIS/DNS rather than
  silently pulling the score toward 50/50.
- Two **escalate-only** overrides sit on top of the weighted blend: if 3+ VirusTotal
  engines flag a URL malicious, or the typosquat check fires, the score is floored at
  90-95% regardless of what the blend says. We deliberately don't add a matching
  "de-escalate" override (e.g. auto-trust anything VirusTotal says is clean) — if
  sources disagree, that's surfaced via the breakdown, not smoothed away.
- The response includes a full `breakdown` (per-source risk value + weight actually
  used) so the UI — and you — can see exactly why the score landed where it did,
  not just the final number.

You can tune `BASE_WEIGHTS` in `holistic.py` directly if you want to weight these
differently (e.g. trust VirusTotal more once you're on a paid tier with more engines).

## Setup

```bash
cd phishing-detector
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
# then edit app.py and paste in your VirusTotal API key
```

A trained model is already included at `model/phishing_model.pkl`, so you can run the
app right away. To retrain (e.g. on an updated dataset):

```bash
python train_model.py --csv /path/to/PhiUSIIL_Phishing_URL_Dataset.csv
```

## Run

```bash
python app.py
```

Then open **http://localhost:5000** in your browser, paste a URL, and hit **Scan**.

## Holistic checks: VirusTotal, WHOIS, DNS

Right after the instant ML verdict, PhishGuard kicks off a second, separate request
(`/api/enrich`) that runs three independent checks in parallel and streams them into
the page as they arrive:

- **VirusTotal** — looks up (or, for URLs it's never seen, submits + polls for) a
  multi-engine scan report: how many of ~90 security vendors flag it, with a link to
  the full report. Needs `VIRUSTOTAL_API_KEY` in app.py — get a free key at
  https://www.virustotal.com/gui/join-us (free tier: 4 requests/min, so don't hammer it).
  If no key is configured, this panel just says so — everything else still works.
- **WHOIS** — registrar, creation/expiration/updated dates, domain age (a domain
  registered days ago is a classic red flag), name servers. Uses `python-whois`, which
  talks to WHOIS servers directly (no API key needed, just normal internet access).
- **DNS** — resolves A, AAAA, MX, NS, and TXT records via `dnspython`, and flags
  domains that don't resolve at all.

This is intentionally a **separate endpoint from `/api/scan`**, not folded into the ML
pipeline — the RandomForest's features and logic are unchanged from before. VirusTotal/
WHOIS/DNS are additional, independent context shown alongside the model's verdict for a
fuller picture, not inputs to it. Every one of these three lookups fails soft (missing
key, rate limit, timeout, no record found) — a failure in one never blocks the others
or the core scan.

## API

`POST /api/scan` — the ML verdict (unchanged):

```json
{ "url": "https://example.com/login" }
```

Response:

```json
{
  "url": "https://example.com/login",
  "label": "legitimate",
  "probability_legitimate": 97.33,
  "probability_phishing": 2.67,
  "domain": "example.com",
  "tld": "com",
  "matched_suspicious_words": ["login"],
  "signals": [ { "label": "Uses HTTPS", "value": "Yes", "risky": false }, ... ]
}
```

`POST /api/enrich` — VirusTotal + WHOIS + DNS:

```json
{ "url": "https://example.com/login" }
```

Response:

```json
{
  "url": "https://example.com/login",
  "domain": "example.com",
  "ml": { "label": "legitimate", "probability_legitimate": 91.2, "...": "..." },
  "virustotal": {
    "available": true, "status": "completed",
    "malicious": 0, "suspicious": 0, "harmless": 68, "undetected": 22,
    "total_engines": 90, "flagged": 0,
    "permalink": "https://www.virustotal.com/gui/url/..."
  },
  "whois": {
    "available": true, "registrar": "...", "creation_date": "1995-08-14T00:00:00",
    "domain_age_days": 11000, "name_servers": ["..."]
  },
  "dns": {
    "available": true, "resolves": true,
    "records": { "A": ["93.184.216.34"], "MX": [], "NS": ["..."], "TXT": [] }
  },
  "holistic": {
    "score": 8.4, "label": "legitimate", "confidence": 91.6,
    "breakdown": [
      { "source": "ml", "available": true, "risk": 0.088, "weight": 0.55 },
      { "source": "virustotal", "available": true, "risk": 0.0, "weight": 0.3 },
      { "source": "whois", "available": true, "risk": 0.05, "weight": 0.1 },
      { "source": "dns", "available": true, "risk": 0.1, "weight": 0.05 }
    ],
    "overrides": [],
    "sources_used": ["ml", "virustotal", "whois", "dns"]
  }
}
```

## Notes & limitations

- This is a heuristic lexical classifier, not a guarantee. Treat a "phishing" verdict
  as a strong warning sign, and a "legitimate" one as "no obvious red flags in the URL
  text" — not proof of safety. Always be cautious entering credentials.
- Because it never fetches the destination page, it can't catch threats that only show
  up in page content (fake login forms on an otherwise clean-looking URL, compromised
  legitimate domains, etc.). For higher accuracy at the cost of speed/reliability, you
  could extend `feature_extractor.py` to also fetch and parse the page (the original
  PhiUSIIL feature set includes those signals).

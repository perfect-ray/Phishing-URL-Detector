# PhishGuard — Phishing URL Scanner
## Project Report

**A Flask web application that classifies URLs as phishing or legitimate, combining a
custom-trained machine learning model with VirusTotal, WHOIS, and DNS intelligence into
one holistic verdict.**

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [System Architecture](#2-system-architecture)
3. [Technology Stack](#3-technology-stack)
4. [Dataset](#4-dataset)
5. [Feature Engineering](#5-feature-engineering)
6. [Model Training](#6-model-training)
7. [Dataset Artifacts Found & Fixed](#7-dataset-artifacts-found--fixed)
8. [Typosquat / Brand-Impersonation Detection](#8-typosquat--brand-impersonation-detection)
9. [Backend API](#9-backend-api)
10. [Third-Party Enrichment: VirusTotal, WHOIS, DNS](#10-third-party-enrichment-virustotal-whois-dns)
11. [Holistic Scoring Algorithm](#11-holistic-scoring-algorithm)
12. [Frontend / UI](#12-frontend--ui)
13. [Project Structure](#13-project-structure)
14. [Setup & Deployment](#14-setup--deployment)
15. [Limitations & Future Work](#15-limitations--future-work)

---

## 1. Project Overview

PhishGuard is a self-contained web application for scoring whether a URL is phishing or
legitimate. It was built in stages:

1. A **machine learning classifier** trained from scratch on the PhiUSIIL Phishing URL
   dataset (235,795 labeled URLs), using only features computable from the URL string
   itself — no page crawling, so a scan is instant and never contacts the destination site.
2. **Typosquat / brand-impersonation detection** layered on top, since lexical features
   alone don't catch things like `g00gle.com` or `paypa1-login.com`.
3. **Third-party enrichment** — VirusTotal (multi-engine scan), WHOIS (domain
   registration/age), and DNS resolution — run in parallel alongside the ML verdict.
4. A **holistic scoring layer** that transparently blends all four sources (ML,
   VirusTotal, WHOIS, DNS) into one combined score and verdict.
5. A dashboard-style **UI** ("PhishGuard") built around a security-console visual theme,
   presenting all of the above without page reloads.

Everything runs locally via `python app.py` — no cloud deployment, no external database.

---

## 2. System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                              BROWSER                                 │
│   templates/index.html + static/app.js + static/style.css            │
│                                                                        │
│   1. User pastes a URL, hits "Scan"                                  │
│   2. POST /api/scan   → instant ML verdict (renders immediately)     │
│   3. POST /api/enrich → VT + WHOIS + DNS + holistic score            │
│      (fired right after #2, renders progressively as it arrives)     │
└───────────────────────────────┬───────────────────────────────────────┘
                                 │ HTTP / JSON
┌────────────────────────────────▼───────────────────────────────────────┐
│                          FLASK APP (app.py)                            │
│                                                                          │
│  /api/scan  ──► predict_url(url)                                       │
│                    │                                                    │
│                    ├─► feature_extractor.extract_features_detail(url)  │
│                    │      (32 lexical/structural + typosquat features) │
│                    │                                                    │
│                    └─► model/phishing_model.pkl.predict_proba(vector)  │
│                           (RandomForestClassifier, scikit-learn)       │
│                                                                          │
│  /api/enrich ──► ThreadPoolExecutor (parallel):                        │
│                    ├─► enrichment.get_virustotal_report(url, api_key)  │
│                    ├─► enrichment.get_whois_info(domain)                │
│                    └─► enrichment.get_dns_info(domain)                  │
│                    then: holistic.compute_holistic(...)                 │
│                    (weighted blend of ML + VT + WHOIS + DNS)           │
└───────────────────────────────┬───────────────────────────────────────┘
                                 │ outbound HTTPS / DNS / WHOIS(port 43)
                 ┌───────────────┼────────────────┐
                 ▼               ▼                ▼
          VirusTotal API   WHOIS servers     DNS resolvers
          (api.virustotal    (via python-      (via dnspython)
           .com/api/v3)       whois, socket)
```

**Design principle: two-speed responses.** `/api/scan` (the ML model) responds in
milliseconds, so the UI shows a verdict immediately. `/api/enrich` (VirusTotal + WHOIS +
DNS) can take several seconds — VirusTotal in particular polls for up to ~12 seconds on
a URL it's never seen before — so it's a **separate, asynchronous request** fired right
after the first one, and the UI streams in results as they arrive rather than blocking
the whole page on the slowest source.

---

## 3. Technology Stack

| Layer                  | Technology                                        | Purpose                                              |
|-------------------------|----------------------------------------------------|-------------------------------------------------------|
| Backend framework       | **Flask 3.x** (Python)                             | HTTP server, routing, JSON APIs                       |
| ML framework            | **scikit-learn** (`RandomForestClassifier`)         | The phishing/legitimate classifier                    |
| Data handling            | **pandas**, **numpy**                              | Dataset loading, feature matrix construction           |
| Model persistence        | **joblib**                                          | Serializing the trained model to `model/phishing_model.pkl` |
| Domain parsing           | **tldextract**                                      | Public-suffix-list-aware domain/subdomain/TLD splitting |
| VirusTotal integration   | **requests**                                        | REST calls to the VirusTotal v3 API                   |
| WHOIS lookups            | **python-whois**                                    | Domain registration data (registrar, dates, name servers) |
| DNS resolution           | **dnspython**                                       | A / AAAA / MX / NS / TXT record lookups                |
| Config / secrets         | **python-dotenv**                                   | Loads `VIRUSTOTAL_API_KEY` from a variable    |
| Concurrency              | **concurrent.futures.ThreadPoolExecutor**            | Runs VT/WHOIS/DNS lookups in parallel, not sequentially |
| Frontend markup/styling  | **HTML5 + hand-written CSS** (CSS custom properties, CSS Grid, Flexbox) | Dashboard UI, no CSS framework dependency |
| Frontend behavior        | **Vanilla JavaScript** (no framework)                | Fetch calls, DOM rendering, gauge/radar animation      |
| Fonts                    | **JetBrains Mono** + **IBM Plex Sans** (Google Fonts) | Terminal/console visual identity                      |
| Data source               | **PhiUSIIL Phishing URL Dataset** (235,795 URLs)     | Model training data                                    |

No database is used — the app is stateless per request; scan history in the UI lives
only in the browser tab's JavaScript memory.

---

## 4. Dataset

**PhiUSIIL Phishing URL Dataset**
- **235,795 rows**, 55 original columns (only the `URL` and `label` columns are used —
  see [Section 5](#5-feature-engineering) for why).
- **Label convention:** `1` = legitimate (134,850 rows), `0` = phishing (100,945 rows).
- The original dataset also includes page-content-derived columns (HTML title, favicon
  presence, image count, etc.) requiring a live crawl of the target page. Those were
  **deliberately excluded** — this project only uses features computable from the URL
  **text itself**, so a scan never needs to fetch the destination page. This is what
  makes `/api/scan` instant and side-effect-free (it doesn't "visit" the site being
  checked, which also means it can't tip off an attacker that their URL is being
  investigated).

---

## 5. Feature Engineering

All feature extraction lives in `feature_extractor.py`, in a single function
(`extract_features`) used identically at **both training time and inference time** —
this guarantees the model never sees a feature computed differently than what the live
app computes.

### 5.1 Feature list (32 features)

| Category | Features |
|---|---|
| **Length / structure** | `URLLength`, `DomainLength`, `TLDLength`, `PathLength`, `NoOfPathSegments`, `NoOfSubDomain`, `NoOfDots` |
| **Domain type** | `IsDomainIP` (raw IP as domain), `HasPort` |
| **Protocol** | `IsHTTPS` |
| **Character composition** | `NoOfLettersInURL`, `LetterRatioInURL`, `NoOfDegitsInURL`, `DegitRatioInURL`, `CharContinuationRate` (longest run of a repeated character) |
| **Punctuation / symbols** | `NoOfEqualsInURL`, `NoOfQMarkInURL`, `NoOfAmpersandInURL`, `NoOfDashInURL`, `NoOfUnderscoreInURL`, `NoOfOtherSpecialCharsInURL`, `SpacialCharRatioInURL`, `HasAtSymbol` |
| **Obfuscation** | `HasObfuscation`, `NoOfObfuscatedChar`, `ObfuscationRatio` (`%`-encoded characters) |
| **Wordlist-based** | `HasSuspiciousWords`, `NoOfSuspiciousWords` (login, verify, secure, banking, etc.) |
| **URL shorteners** | `IsShortenedURL` (bit.ly, tinyurl.com, etc.) |
| **Brand impersonation** | `IsBrandExactMatch`, `IsTyposquatSuspected`, `BrandEditDistance` (see [Section 8](#8-typosquat--brand-impersonation-detection)) |

### 5.2 Domain parsing

Domain/subdomain/suffix splitting uses **`tldextract`**, which is Public-Suffix-List
aware. This matters because naive "split on dots, last label is the TLD" logic breaks
on multi-part suffixes:

- `hdfc.bank.in` → domain **`hdfc`**, suffix **`bank.in`** (correct)
  vs. naive splitting → domain `bank`, TLD `in` (**wrong** — this was a real bug found
  and fixed during development; see [Section 7](#7-dataset-artifacts-found--fixed)).
- Also handles `.co.uk`, `.com.au`, `.co.in`, `.gov.in`, etc. correctly.

---

## 6. Model Training

**Algorithm:** `RandomForestClassifier` (scikit-learn), an ensemble of decision trees
using majority voting / probability averaging.

**Final hyperparameters** (`train_model.py`):

```python
RandomForestClassifier(
    n_estimators=150,
    max_depth=14,
    min_samples_leaf=4,
    n_jobs=-1,
    random_state=42,
    class_weight="balanced_subsample",
)
```

These were tuned down from an initial `n_estimators=300, max_depth=20` — the larger
forest gave a negligible accuracy improvement (~0.4 percentage points) but produced an
**89 MB model file**; the smaller forest is **16 MB** with virtually the same accuracy,
which matters for load time and repo size.

**Training procedure:**
1. Load the CSV, drop rows with missing `URL`/`label`.
2. **Augment legitimate URLs** to remove dataset artifacts (see [Section 7](#7-dataset-artifacts-found--fixed)).
3. Extract all 32 features from every URL via `feature_extractor.extract_features_vector`.
4. 80/20 stratified train/test split (`random_state=42`).
5. Fit the RandomForest on the training set.
6. Evaluate on the held-out test set; save the model + metrics with `joblib`.

**Final performance (held-out 20% test set, 47,159 URLs):**

| Metric | Value |
|---|---|
| Accuracy | **97.79%** |
| ROC AUC | **99.43%** |
| Precision (phishing) | 0.99 |
| Recall (phishing) | 0.96 |
| Precision (legitimate) | 0.97 |
| Recall (legitimate) | 0.99 |

**Top feature importances (final model):**

| Rank | Feature | Importance |
|---|---|---|
| 1 | `IsHTTPS` | 35.2% |
| 2 | `PathLength` | 11.3% |
| 3 | `CharContinuationRate` | 9.5% |
| 4 | `NoOfDegitsInURL` | 6.9% |
| 5 | `DomainLength` | 6.6% |
| 6 | `NoOfPathSegments` | 5.6% |
| 7 | `DegitRatioInURL` | 5.0% |
| 8 | `NoOfDots` | 4.7% |
| 9 | `URLLength` | 4.1% |
| 10 | `NoOfSubDomain` | 2.5% |

**Inference:** for a submitted URL, `extract_features_detail(url)` produces the 32-value
feature vector, `model.predict_proba(vector)` returns `[P(phishing), P(legitimate)]`,
and the higher probability determines the label.

---

## 7. Dataset Artifacts Found & Fixed

A significant part of this project was discovering and correcting **spurious shortcuts**
the model was learning from quirks in how the dataset was collected, rather than from
genuine phishing signals. Each was found via a real false positive/negative reported
during testing, root-caused, fixed, and verified with a regression test battery.

### 7.1 "Any path at all ⇒ phishing"

**Symptom:** `https://www.google.com` was classified legitimate, but
`https://www.google.com/` (trailing slash) or `https://www.google.com/search?q=x` was
flagged as phishing.

**Root cause:** in the raw dataset, **100% of the 134,850 legitimate-labeled URLs have
zero path** — they were collected as bare `scheme://domain` strings, while phishing
URLs (captured from live phishing feeds) almost always have a path. The model learned
"any path present ⇒ phishing" as a shortcut.

**Fix:** `train_model.py`'s `augment_legitimate_urls()` appends a realistic path (from a
pool of ~35 templates: `/about`, `/search?q=...`, `/login`, `/products/123`, etc.) to a
random 50% of legitimate training URLs before feature extraction, so the model can't
rely on path-presence alone.

### 7.2 "No `www.` prefix ⇒ phishing"

**Symptom:** `www.google.com` passed, but `github.com` (no `www.`) was flagged
phishing.

**Root cause:** **100% of legitimate URLs in the dataset start with `www.`** — again a
collection artifact. The model learned the presence of `www.` as a legitimacy signal.

**Fix:** the same `augment_legitimate_urls()` function also strips `www.` from a random
45% of legitimate training URLs.

### 7.3 TLD/subdomain miscounting on multi-part suffixes

**Symptom:** `https://www.hdfc.bank.in` (a real HDFC Bank domain under India's RBI-backed
`.bank.in` banking namespace) was flagged as phishing.

**Root cause:** naive dot-splitting treated `in` as the TLD and `bank` as the
second-level domain, which (a) miscounted the subdomain depth and (b) fed `bank` into
the typosquat checker, where it matched `usbank` within edit-distance 2 — a false
positive collision between a generic word fragment and an unrelated brand name.

**Fix:** replaced naive splitting with `tldextract` (Section 5.2), which correctly
resolves `hdfc.bank.in` → domain `hdfc`, suffix `bank.in`.

### 7.4 Typosquats under-weighted by the model

**Symptom:** `g00gle.com` (digits substituted for look-alike letters) was scored
legitimate.

**Root cause:** typosquatting patterns are rare in the training data, so the RandomForest
assigned them low importance even after the feature was added.

**Fix:** rather than only relying on the model's learned weight, `app.py` applies a
deterministic floor: if the typosquat check fires (and it's not the brand's real exact
domain), the phishing probability is floored at 93% (see Section 8).

---

## 8. Typosquat / Brand-Impersonation Detection

A dedicated rule-based check in `feature_extractor.py`, run alongside the ML features,
since character-substitution attacks (`g00gle.com`, `paypa1-login.com`) don't
necessarily look unusual by generic length/ratio metrics.

**Algorithm (`_brand_features`):**

1. Maintain a curated list of ~50 frequently-impersonated brand names (Google, PayPal,
   Amazon, Microsoft, major banks, shipping carriers, etc.).
2. Normalize the domain's second-level label using a leetspeak substitution map
   (`0→o, 1→l, 3→e, 4→a, 5→s, 7→t, $→s, @→a`, plus `vv→w`, `rn→m`).
3. Also split the label on hyphens, so compound domains like `paypa1-login.com` are
   checked token-by-token (`paypa1`, `login`) as well as whole.
4. For each token: check for an **exact match** to a brand (embedded verbatim in a
   larger domain = classic combosquatting), a **leet-normalized exact match**
   (`g00gle` → `google`), or a **bounded Levenshtein edit distance** (≤2 for longer brand
   names, ≤1 for short ones like `dhl`/`att` — this stricter bound for short brands
   prevents generic 3-letter words from accidentally colliding with short brand codes).
5. Output three features: `IsBrandExactMatch` (this domain *is* the real brand),
   `IsTyposquatSuspected`, `BrandEditDistance`.

**Deterministic override:** because this signal is rare in training data and thus
under-weighted by the RandomForest alone, `app.py`'s `predict_url()` floors the phishing
probability at **93%** whenever `IsTyposquatSuspected` is true and it isn't the brand's
real exact domain — treating this as a high-precision rule rather than leaving it purely
to the model's learned weight.

**Verified against:** `g00gle.com`, `paypa1-login.com`, `arnazon.com`,
`microsooft.com`, `chase-account-verify.com` (all correctly flagged) while avoiding
false positives on `applesauce-recipes.com`, `the-guardian.com`, `att.com`, and other
brand-adjacent-but-legitimate domains.

---

## 9. Backend API

All routes are defined in `app.py`.

### `GET /`
Renders the main UI (`templates/index.html`), passing in the model's held-out accuracy/
AUC and whether a VirusTotal API key is configured.

### `POST /api/scan`
The fast, ML-only verdict. Never touches the network beyond parsing the URL string.

**Request:**
```json
{ "url": "https://example.com/login" }
```

**Response:**
```json
{
  "url": "https://example.com/login",
  "label": "legitimate",
  "probability_legitimate": 97.33,
  "probability_phishing": 2.67,
  "domain": "example.com",
  "tld": "com",
  "matched_suspicious_words": ["login"],
  "signals": [
    { "label": "Uses HTTPS", "value": "Yes", "risky": false },
    "... one entry per human-readable signal ..."
  ]
}
```

### `POST /api/enrich`
Runs VirusTotal, WHOIS, and DNS **in parallel** (via `ThreadPoolExecutor`), re-runs the
ML prediction for consistency, and computes the holistic score. Slower (VirusTotal may
poll for several seconds on a URL it hasn't seen), so it's called as a follow-up request
after `/api/scan`, not merged into it.

**Response** (abbreviated — see `README.md` for the full schema):
```json
{
  "url": "...", "domain": "...",
  "ml": { "label": "legitimate", "probability_legitimate": 91.2, "...": "..." },
  "virustotal": { "available": true, "status": "completed", "malicious": 0, "...": "..." },
  "whois": { "available": true, "domain_age_days": 11000, "...": "..." },
  "dns": { "available": true, "resolves": true, "records": { "A": ["..."], "...": "..." } },
  "holistic": { "score": 8.4, "label": "legitimate", "confidence": 91.6, "breakdown": [...], "overrides": [] }
}
```

### `GET /healthz`
Trivial liveness check (`{"status": "ok"}`).

---

## 10. Third-Party Enrichment: VirusTotal, WHOIS, DNS

All in `enrichment.py`. Every function **fails soft** — a missing API key, timeout, or
lookup failure returns `{"available": false, "reason": "..."}` instead of raising, so
one broken source never breaks the scan or the other two sources.

### 10.1 VirusTotal (`get_virustotal_report`)
- Computes the VirusTotal "URL ID" (`base64.urlsafe_b64encode(url).strip("=")`).
- `GET /api/v3/urls/{id}` — if VirusTotal has already scanned this exact URL, returns
  the cached multi-engine report immediately.
- If unseen (`404`): `POST /api/v3/urls` to submit it, then polls
  `GET /api/v3/analyses/{analysis_id}` every 3 seconds (up to 4 attempts) until the
  analysis completes. If still pending after that, returns a `"pending"` status with a
  link to check back later rather than blocking indefinitely.
- Extracts `last_analysis_stats` (malicious / suspicious / harmless / undetected counts
  across ~70-90 antivirus/security engines) and a permalink to the full report.
- Requires `VIRUSTOTAL_API_KEY` in app.py (free tier: 4 requests/minute).

### 10.2 WHOIS (`get_whois_info`)
- Uses `python-whois`, which queries WHOIS servers directly over TCP port 43 (no API
  key needed).
- Extracts registrar, creation/expiration/updated dates, name servers, org, country.
- Computes **domain age in days** — the single most useful WHOIS signal for phishing
  detection, since attacker-registered domains are typically hours-to-days old.

### 10.3 DNS (`get_dns_info`)
- Uses `dnspython` to resolve `A`, `AAAA`, `MX`, `NS`, and `TXT` records independently
  (a failure on one record type doesn't block the others).
- Reports whether the domain resolves at all — a domain that doesn't resolve is
  suspicious (dead/parked/sinkholed) but not definitively malicious on its own.

---

## 11. Holistic Scoring Algorithm

`holistic.py` — a **presentation/aggregation layer only**; it does not modify the
RandomForest model, its features, or `/api/scan`'s output in any way. It runs downstream,
combining the outputs of Sections 6, 9, and 10 into one transparent score.

### 11.1 Per-source risk value

| Source | Risk value (0 = fine, 1 = bad) | Base weight |
|---|---|---|
| ML model | `probability_phishing` directly | **55%** |
| VirusTotal | `flagged_engines / total_engines` | **30%** |
| WHOIS | Domain-age-based step function (< 7 days → 0.95, < 30 → 0.80, < 90 → 0.55, < 365 → 0.30, < 3 years → 0.15, else → 0.05) | **10%** |
| DNS | 0.10 if it resolves, 0.65 if it doesn't | **5%** |

### 11.2 Combination rules

1. **Unavailable sources are excluded, not defaulted to neutral.** If VirusTotal has no
   API key configured, its 30% weight is redistributed proportionally across whichever
   of ML/WHOIS/DNS *are* available — the score is never silently pulled toward 50/50 by
   a missing input.
2. **Weighted sum** across available sources produces the base score.
3. **Escalate-only overrides** (never de-escalate):
   - If VirusTotal shows **≥3 engines** flagging the URL malicious → floor the score at
     **95%**.
   - If the typosquat check fires → floor the score at **90%**.
   - There is **no equivalent override toward "trust it"** — e.g. VirusTotal showing 0
     detections never force-overrides a high ML score. If sources genuinely disagree,
     that's surfaced in the UI's per-source breakdown rather than smoothed away.
4. Final label: `phishing` if score ≥ 50%, else `legitimate`.

The API response includes the full `breakdown` array (each source's risk value and the
weight actually used), so both the UI and any API consumer can see exactly why the score
landed where it did.

---

## 12. Frontend / UI

**Stack:** server-rendered Jinja2 template (`templates/index.html`) + one CSS file
(`static/style.css`) + one vanilla-JS file (`static/app.js`). No build step, no
frontend framework — everything is static assets served directly by Flask.

### 12.1 Visual design system
A "security console" theme, chosen to fit the subject matter (a threat-scanning tool)
rather than a generic dashboard look:

- **Palette:** deep ink-navy background (`#0B0E13`), with three distinct accent colors
  used contextually — green (`#33D69F`) for "safe"/scanning, amber (`#F2B84B`) for
  in-progress/caution, red (`#FF6259`) for danger, plus cyan (`#5DD8E8`) for
  links/secondary data.
- **Typography:** `JetBrains Mono` for headings and all data/numbers (terminal feel),
  `IBM Plex Sans` for body copy.
- **Signature motif:** a radar-sweep SVG animation plays while a scan is in flight,
  resolving into a semicircular gauge (SVG arc + rotating needle) that points from
  green (safe) to red (danger) based on the phishing probability.
- A subtle CSS scanline overlay and soft radial-gradient glows reinforce the
  console/terminal atmosphere without being distracting.

### 12.2 Layout
- **Header:** brand mark + live model accuracy chip.
- **Hero:** two-column — left is the URL input console (`›` prompt style, matching the
  terminal theme); right is a static preview of the four checks the tool runs (ML,
  VirusTotal, WHOIS, DNS), so the space isn't empty before a scan.
- **Results:** a **12-column CSS Grid dashboard** (not a single stacked column):
  - Verdict gauge (7/12 width) and signal breakdown (5/12 width) side by side.
  - Holistic verdict as a full-width (12/12) banner — headline on the left, per-source
    weighted bars filling the rest of the row.
  - VirusTotal / WHOIS / DNS panels as **three equal columns** (4/12 each) in one row.
  - Collapses to a single column below ~860px viewport width.
- **Scan history:** a responsive multi-column card grid (not a stacked list), holding
  the last 6 scans from the current session (in-memory only, not persisted).

### 12.3 Client-side flow (`app.js`)
1. On submit, `POST /api/scan` → render the gauge, verdict label, and signal list as
   soon as it returns (typically well under a second).
2. Immediately after, fire `POST /api/enrich` in the background — render a loading
   panel, then populate the holistic verdict, VirusTotal, WHOIS, and DNS panels as the
   response arrives, without blocking or re-disabling the scan button.
3. All rendering is done via direct DOM manipulation (`document.createElement`) — no
   templating library.

---

## 13. Project Structure

```
phishing-detector/
├── app.py                  # Flask app: routes /, /api/scan, /api/enrich, /healthz
├── feature_extractor.py    # URL -> 32-feature vector; shared by training & serving
├── enrichment.py           # VirusTotal / WHOIS / DNS lookups (fail-soft, independent)
├── holistic.py             # Combines ML + VT + WHOIS + DNS into one score (display-only)
├── train_model.py          # Loads CSV, augments data, trains & saves the RandomForest
├── requirements.txt        # Flask, scikit-learn, pandas, requests, python-whois,
│                            #   dnspython, tldextract, python-dotenv, joblib, numpy
├── model/
│   └── phishing_model.pkl  # Trained model + metadata (accuracy, ROC AUC), ~16 MB
├── templates/
│   └── index.html          # Single-page UI (Jinja2)
├── static/
│   ├── style.css           # Design system + dashboard grid layout
│   └── app.js               # Fetch calls, DOM rendering, gauge/radar animation
└── docs/
    └── PROJECT_REPORT.md   # This document
```

---

## 14. Setup & Deployment

```bash
cd phishing-detector
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python app.py                     # serves on http://localhost:5000
```

To retrain the model on an updated dataset:
```bash
python train_model.py --csv /path/to/PhiUSIIL_Phishing_URL_Dataset.csv
```

No database, no external services are required to run the core ML scanner — VirusTotal/
WHOIS/DNS enrichment degrades gracefully (each shows "unavailable" individually) if
network access or an API key isn't present.

---

## 15. Limitations & Future Work

- **Lexical-only ML model.** It never inspects page content, so it can't catch a
  phishing page hosted on an otherwise clean-looking, previously-legitimate, or
  compromised domain — that class of attack is exactly what VirusTotal's crawling
  engines help cover in the holistic score.
- **Brand list is hand-curated (~50 names).** Typosquats of brands outside that list
  won't trigger the dedicated detector (though the base ML features may still catch
  some of them incidentally).
- **VirusTotal free tier is rate-limited** (4 requests/minute) and first-time scans of
  unseen URLs can take up to ~12 seconds to resolve in this app before falling back to
  a "pending" state.
- **WHOIS coverage varies by TLD/registrar**, and some registrars redact data via
  privacy proxies, which shows as "unavailable" rather than a false signal.
- **Holistic weights are static**, not learned — they're a reasonable, explainable
  starting point (`BASE_WEIGHTS` in `holistic.py`) rather than optimized against
  labeled holistic-outcome data (which would require a labeled dataset of VT/WHOIS/DNS
  outcomes paired with ground truth, which wasn't available here).
- **No persistence layer.** Scan history is UI-only and resets on page reload; there's
  no database of past scans, users, or feedback loop to retrain the model over time.

"""
train_model.py

Trains a phishing-URL classifier on the PhiUSIIL dataset using ONLY
features that can be computed from the raw URL string (see
feature_extractor.py). This is what lets the deployed Flask app score any
URL the user types in, instantly, without crawling the target page.

Usage:
    python train_model.py --csv /path/to/PhiUSIIL_Phishing_URL_Dataset.csv
"""

import argparse
import random
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from feature_extractor import FEATURE_NAMES, extract_features_vector

# Realistic paths used to augment bare-domain legitimate URLs. Without this,
# every legitimate URL in PhiUSIIL is a bare "scheme://domain" with zero
# path, while phishing URLs almost always have one — so a naive model just
# learns "any path => phishing", which fails on real traffic (e.g.
# https://www.google.com/search?q=...). Mixing realistic paths into the
# legitimate class breaks that shortcut.
#
# A bare trailing slash ("/") is deliberately weighted separately (not just
# folded into PATH_POOL below) because it's one of the most common path
# forms in real browsing -- typing a domain and hitting enter often shows
# up as "domain.com/". Treating it as "just one of 35 pool options" made it
# rare enough in training that a bare-apex-domain-plus-trailing-slash URL
# (e.g. "google.com/", no www, nothing after the slash) could still tip
# toward "phishing" -- a real bug found via manual testing after the initial
# fix. ROOT_SLASH_PROB controls how often the bare slash is chosen instead.
ROOT_SLASH_PROB = 0.30
PATH_POOL = [
    "/index.html", "/about", "/about-us", "/contact", "/contact-us",
    "/login", "/signin", "/account", "/products", "/product/12345",
    "/blog", "/blog/2024/03/article-title", "/search?q=example+query",
    "/news/latest-headlines", "/support", "/help", "/careers", "/en/home",
    "/category/electronics", "/user/profile", "/cart", "/checkout",
    "/api/v1/users", "/docs/getting-started", "/pricing", "/faq",
    "/terms", "/privacy-policy", "/2024/03/15/breaking-news",
    "/watch?v=dQw4w9WgXcQ", "/videos/123456", "/store/item?id=42",
    "/wiki/Main_Page", "/settings", "/dashboard", "/download",
]


def _pick_path(rng: random.Random) -> str:
    if rng.random() < ROOT_SLASH_PROB:
        return "/"
    return rng.choice(PATH_POOL)


def augment_legitimate_urls(
    df: pd.DataFrame,
    path_frac: float = 0.5,
    strip_www_frac: float = 0.45,
    seed: int = 42,
) -> pd.DataFrame:
    """Fix two PhiUSIIL dataset artifacts in the legitimate (label=1) class:

    1. Every legitimate URL has zero path (bare "scheme://domain"), while
       phishing URLs almost always have one -> the model learns "any path
       => phishing", which fails on real traffic like google.com/search.
    2. Every legitimate URL starts with "www.", while phishing URLs are a
       mix -> the model learns "no www => phishing", which fails on real
       apex-domain sites like github.com or stackoverflow.com.

    We fix both by mutating a random subset of legitimate URLs: stripping
    "www." from some, and appending a realistic path to some (independently
    sampled, so some rows get both).
    """
    rng = random.Random(seed)
    df = df.copy()
    legit_idx = list(df.index[df["label"] == 1])

    strip_idx = set(rng.sample(legit_idx, int(len(legit_idx) * strip_www_frac)))
    path_idx = set(rng.sample(legit_idx, int(len(legit_idx) * path_frac)))

    for idx in legit_idx:
        url = str(df.at[idx, "URL"])
        if idx in strip_idx:
            url = url.replace("://www.", "://", 1)
        if idx in path_idx:
            url = url + _pick_path(rng)
        df.at[idx, "URL"] = url
    return df


def build_feature_matrix(urls: pd.Series) -> np.ndarray:
    rows = [extract_features_vector(u) for u in urls]
    return np.array(rows, dtype=float)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", required=True, help="Path to PhiUSIIL CSV")
    parser.add_argument("--out", default="model/phishing_model.pkl")
    args = parser.parse_args()

    print(f"Loading {args.csv} ...")
    df = pd.read_csv(args.csv)
    print(f"  {len(df):,} rows")

    # label: 1 = legitimate, 0 = phishing (PhiUSIIL convention)
    df = df.dropna(subset=["URL", "label"])

    print("Augmenting legitimate URLs to remove dataset artifacts (all-www, all-bare-path) ...")
    df = augment_legitimate_urls(df, path_frac=0.5, strip_www_frac=0.45, seed=42)

    print("Extracting lexical features from raw URLs ...")
    t0 = time.time()
    X = build_feature_matrix(df["URL"])
    y = df["label"].astype(int).values
    print(f"  done in {time.time() - t0:.1f}s, feature matrix shape {X.shape}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Training RandomForestClassifier ...")
    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=14,
        min_samples_leaf=4,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced_subsample",
    )
    t0 = time.time()
    clf.fit(X_train, y_train)
    print(f"  trained in {time.time() - t0:.1f}s")

    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_proba)
    print(f"\nAccuracy: {acc:.4f}")
    print(f"ROC AUC:  {auc:.4f}")
    print("\nClassification report (0=phishing, 1=legitimate):")
    print(classification_report(y_test, y_pred, target_names=["phishing", "legitimate"]))
    print("Confusion matrix:")
    print(confusion_matrix(y_test, y_pred))

    importances = sorted(
        zip(FEATURE_NAMES, clf.feature_importances_), key=lambda x: -x[1]
    )
    print("\nTop feature importances:")
    for name, imp in importances[:15]:
        print(f"  {name:30s} {imp:.4f}")

    joblib.dump(
        {
            "model": clf,
            "feature_names": FEATURE_NAMES,
            "accuracy": acc,
            "roc_auc": auc,
        },
        args.out,
    )
    print(f"\nSaved model to {args.out}")


if __name__ == "__main__":
    main()

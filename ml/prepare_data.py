from __future__ import annotations
from pathlib import Path
import pandas as pd
import random
from urllib.parse import urlparse

def canonicalize(u: str) -> str:
    u = u.strip().lower()
    if not u.startswith(("http://", "https://")):
        u = "http://" + u
    try:
        p = urlparse(u)
    except ValueError:
        return ""

    host = (p.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]

    path = p.path or "/"
    if path != "/":
        path = path.rstrip("/")

    return host + path
RAW_DIR = Path(__file__).resolve().parent / "data" / "raw"
OUT_DIR = Path(__file__).resolve().parent / "data" / "processed"
OUT_DIR.mkdir(parents=True, exist_ok=True)

OUT_PATH = Path(__file__).resolve().parent / "data" / "urls.csv"

RANDOM_SEED = 42
random.seed(RANDOM_SEED)

# Canonical mapping for binary phishing vs benign
LABEL_MAP = {
    "benign": 0,
    "phishing": 1,
}

def _find_col(df: pd.DataFrame, candidates: list[str]) -> str | None:
    lower = {c.lower(): c for c in df.columns}
    for cand in candidates:
        if cand.lower() in lower:
            return lower[cand.lower()]
    return None

def load_kaggle_malicious_urls(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)

    url_col = _find_col(df, ["url", "URL"])
    label_col = _find_col(df, ["type", "label", "category", "class"])

    if url_col is None:
        # fall back: assume first column is url
        url_col = df.columns[0]
    if label_col is None:
        # fall back: assume second column is label if exists
        if df.shape[1] < 2:
            raise ValueError("Dataset must have at least 2 columns (url + label/type).")
        label_col = df.columns[1]

    out = df[[url_col, label_col]].copy()
    out.columns = ["url", "label_name"]

    out["url"] = out["url"].astype(str).str.strip()
    out["label_name"] = out["label_name"].astype(str).str.strip().str.lower()

    # normalize a few common variants
    out["label_name"] = out["label_name"].replace({
        "defacement_url": "defacement",
        "defacement urls": "defacement",
        "phish": "phishing",
    })

    # keep only binary labels
    out = out[out["label_name"].isin(LABEL_MAP.keys())].copy()
    out["label"] = out["label_name"].map(LABEL_MAP).astype(int)

    # basic cleaning
    out = out.dropna(subset=["url", "label"]).copy()

    # Canonicalize before resolving duplicates (CRITICAL)
    out["canon"] = out["url"].astype(str).apply(canonicalize)
    out = out[out["canon"].str.len() > 0].copy()

    # Resolve conflicting labels for the same canonical URL (majority vote)
    out = (
        out.groupby("canon", as_index=False)
           .agg(label_name=("label_name", lambda s: s.value_counts().idxmax()))
    )

    out["label"] = out["label_name"].map(LABEL_MAP).astype(int)

    # Use canonical URL for training
    out["url"] = out["canon"]
    out = out.drop(columns=["canon"]).reset_index(drop=True)
    return out

def normalize(df: pd.DataFrame) -> pd.DataFrame:
    # drop empty urls + whitespace
    df = df[df["url"].str.len() > 0].copy()
    # drop obvious non-urls: spaces inside
    df = df[~df["url"].str.contains(r"\s", regex=True)].copy()
    return df

def main():
    # Kaggle dataset file name is usually something like "malicious_phish.csv"
    # Put it under: ml/data/raw/
    kaggle_path = RAW_DIR / "malicious_phish.csv"
    if not kaggle_path.exists():
        raise FileNotFoundError(
            f"Missing {kaggle_path}\n"
            "Put the Kaggle CSV at: ml/data/raw/malicious_phish.csv"
        )

    df = load_kaggle_malicious_urls(kaggle_path)
    df = normalize(df)
    def _is_parseable(u: str) -> bool:
        try:
            u = u.strip()
            if not (u.startswith("http://") or u.startswith("https://")):
                u = "http://" + u
            urlparse(u)
            return True
        except ValueError:
            return False

    df = df[df["url"].astype(str).apply(_is_parseable)].copy()
    # Shuffle
    df = df.sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT_PATH, index=False)

    print("Saved:", OUT_PATH)
    print("Counts:\n", df["label_name"].value_counts())

if __name__ == "__main__":
    main()

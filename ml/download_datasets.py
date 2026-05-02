from __future__ import annotations

import argparse
import io
import zipfile
from pathlib import Path

import pandas as pd
import requests


ML_DIR = Path(__file__).resolve().parent
RAW_DIR = ML_DIR / "data" / "raw"
OUT_PATH = ML_DIR / "data" / "urls.csv"

URLHAUS_RECENT_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"
TRANCO_TOP_1M_ZIP = "https://tranco-list.eu/top-1m.csv.zip"


def download_bytes(url: str, timeout: float = 60.0) -> bytes:
    response = requests.get(url, timeout=timeout, headers={"User-Agent": "URLTrustScorer/0.2"})
    response.raise_for_status()
    return response.content


def load_urlhaus(limit: int) -> pd.DataFrame:
    raw = download_bytes(URLHAUS_RECENT_CSV)
    path = RAW_DIR / "urlhaus_recent.csv"
    path.write_bytes(raw)

    df = pd.read_csv(
        io.BytesIO(raw),
        comment="#",
        header=None,
        names=[
            "dateadded",
            "url",
            "url_status",
            "last_online",
            "threat",
            "tags",
            "urlhaus_link",
            "reporter",
        ],
        on_bad_lines="skip",
    )
    df = df[["url"]].dropna().copy()
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"].str.len() > 0].drop_duplicates()
    if limit > 0:
        df = df.head(limit)
    df["label_name"] = "phishing"
    df["label"] = 1
    return df[["url", "label", "label_name"]]


def load_tranco(limit: int) -> pd.DataFrame:
    raw = download_bytes(TRANCO_TOP_1M_ZIP)
    zip_path = RAW_DIR / "tranco_top_1m.csv.zip"
    zip_path.write_bytes(raw)

    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        csv_name = next(name for name in zf.namelist() if name.endswith(".csv"))
        with zf.open(csv_name) as f:
            df = pd.read_csv(f, header=None, names=["rank", "domain"])

    df = df[["domain"]].dropna().copy()
    df["domain"] = df["domain"].astype(str).str.strip().str.lower()
    df = df[df["domain"].str.contains(".", regex=False)].drop_duplicates()
    if limit > 0:
        df = df.head(limit)
    df["url"] = "https://" + df["domain"]
    df["label_name"] = "benign"
    df["label"] = 0
    return df[["url", "label", "label_name"]]


def main() -> None:
    parser = argparse.ArgumentParser(description="Download public URL datasets for URL Trust Scorer.")
    parser.add_argument("--malicious-limit", type=int, default=50000)
    parser.add_argument("--benign-limit", type=int, default=50000)
    args = parser.parse_args()

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    malicious = load_urlhaus(args.malicious_limit)
    benign = load_tranco(args.benign_limit)
    df = pd.concat([malicious, benign], ignore_index=True)
    df = df.drop_duplicates(subset=["url"]).sample(frac=1.0, random_state=42).reset_index(drop=True)
    df.to_csv(OUT_PATH, index=False)

    print(f"Saved dataset: {OUT_PATH}")
    print(df["label_name"].value_counts().to_string())


if __name__ == "__main__":
    main()

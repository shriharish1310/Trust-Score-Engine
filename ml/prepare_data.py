from __future__ import annotations
from pathlib import Path
import pandas as pd
import random

RAW_DIR = Path(__file__).resolve().parent / "data" / "raw"
OUT_DIR = Path(__file__).resolve().parent / "data" / "processed"
OUT_DIR.mkdir(parents=True, exist_ok=True)

OUT_PATH = Path(__file__).resolve().parent / "data" / "urls.csv"

RANDOM_SEED = 42
random.seed(RANDOM_SEED)
COMMON_BENIGN_PATHS = [
    "/", "/about", "/contact", "/products", "/blog", "/news",
    "/login", "/account", "/search?q=test", "/index.html",
    "/docs", "/help", "/pricing", "/careers"
]
def load_urlhaus(path: Path) -> pd.Series:
    # URLhaus csv_online has comment lines starting with '#'
    # and then a CSV header line:
    # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter

    df = pd.read_csv(
        path,
        comment="#",
        header=None,   # we will assign names ourselves (more robust)
        names=[
            "id",
            "dateadded",
            "url",
            "url_status",
            "last_online",
            "threat",
            "tags",
            "urlhaus_link",
            "reporter",
        ],
        engine="python",  # more tolerant
    )

    # Sometimes the header row may still appear as a data row; drop it if present
    df = df[df["url"] != "url"]

    return df["url"].dropna().astype(str)



def load_tranco(path: Path) -> pd.Series:
    df = pd.read_csv(path, header=None)

    if df.shape[1] >= 2:
        domains = df.iloc[:, 1].astype(str)
    else:
        domains = df.iloc[:, 0].astype(str)

    domains = domains.str.strip().dropna()
    base_urls = "https://" + domains

    # Expand to look like real benign browsing behavior
    expanded = []
    for u in base_urls.tolist():
        for p in COMMON_BENIGN_PATHS:
            expanded.append(u.rstrip("/") + p)

    return pd.Series(expanded)


def normalize(urls: pd.Series) -> pd.Series:
    urls = urls.astype(str).str.strip()
    urls = urls[urls.str.len() > 0]
    # drop obvious non-urls
    urls = urls[~urls.str.contains(r"\s", regex=True)]
    # keep only http/https or bare domains (we add scheme later in features anyway)
    return urls.drop_duplicates()

def main():
    urlhaus_path = RAW_DIR / "urlhaus.csv"
    tranco_path = RAW_DIR / "tranco.csv"

    if not urlhaus_path.exists():
        raise FileNotFoundError(f"Missing {urlhaus_path}")
    if not tranco_path.exists():
        raise FileNotFoundError(f"Missing {tranco_path}")

    mal = normalize(load_urlhaus(urlhaus_path))
    ben = normalize(load_tranco(tranco_path))

    # Balance classes (important)
    n = min(len(mal), len(ben), 50000)  # cap to keep training fast
    mal = mal.sample(n=n, random_state=RANDOM_SEED)
    ben = ben.sample(n=n, random_state=RANDOM_SEED)

    df = pd.DataFrame({
        "url": pd.concat([ben, mal], ignore_index=True),
        "label": [0]*n + [1]*n
    })

    # Shuffle
    df = df.sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT_PATH, index=False)

    print("Saved:", OUT_PATH)
    print("Counts:\n", df["label"].value_counts())

if __name__ == "__main__":
    main()

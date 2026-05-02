from __future__ import annotations

import csv
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import tldextract


DATA_PATH = Path(__file__).resolve().parents[2] / "ml" / "data" / "urls.csv"


def canonicalize_for_reputation(url: str) -> str:
    value = (url or "").strip()
    if not value:
        return ""
    if "://" not in value:
        value = "https://" + value

    try:
        parsed = urlparse(value)
    except ValueError:
        return ""

    scheme = (parsed.scheme or "https").lower()
    host = (parsed.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]

    port = parsed.port
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = host if port is None or default_port else f"{host}:{port}"

    path = parsed.path or ""
    if path == "/":
        path = ""
    elif path:
        path = path.rstrip("/")

    return urlunparse((scheme, netloc, path, "", "", ""))


def registered_domain(url: str) -> str:
    value = url if "://" in url else "https://" + url
    try:
        host = (urlparse(value).hostname or "").lower()
    except ValueError:
        return ""
    if host.startswith("www."):
        host = host[4:]
    ext = tldextract.extract(host)
    return ".".join(part for part in (ext.domain, ext.suffix) if part)


@lru_cache(maxsize=1)
def load_dataset_reputation() -> dict[str, set[str]]:
    benign_domains: set[str] = set()
    malicious_urls: set[str] = set()

    if not DATA_PATH.exists():
        return {"benign_domains": benign_domains, "malicious_urls": malicious_urls}

    with DATA_PATH.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row.get("url", "")
            label_name = (row.get("label_name") or "").strip().lower()
            label = (row.get("label") or "").strip()
            canonical = canonicalize_for_reputation(url)
            if not canonical:
                continue

            if label_name == "benign" or label == "0":
                rd = registered_domain(canonical)
                if rd:
                    benign_domains.add(rd)
            elif label_name in {"phishing", "malicious"} or label == "1":
                malicious_urls.add(canonical)

    return {"benign_domains": benign_domains, "malicious_urls": malicious_urls}


def dataset_reputation(url: str) -> dict:
    canonical = canonicalize_for_reputation(url)
    rd = registered_domain(canonical)
    data = load_dataset_reputation()
    exact_malicious = canonical in data["malicious_urls"]
    known_benign_domain = bool(rd and rd in data["benign_domains"])

    if exact_malicious:
        verdict = "known_malicious_url"
        risk = 1.0
        detail = "Exact URL matched the local malicious URL dataset."
    elif known_benign_domain:
        verdict = "known_benign_domain"
        risk = 0.0
        detail = "Registered domain appears in the local Tranco benign-domain dataset."
    else:
        verdict = "unknown"
        risk = 0.35
        detail = "No exact malicious URL match or benign-domain reputation match was found locally."

    return {
        "canonical_url": canonical,
        "registered_domain": rd,
        "verdict": verdict,
        "risk": risk,
        "detail": detail,
        "known_benign_domain": known_benign_domain,
        "exact_malicious": exact_malicious,
    }

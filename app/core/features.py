from __future__ import annotations
import math
import re
from dataclasses import dataclass
from urllib.parse import urlparse, unquote

import tldextract


SUSPICIOUS_TOKENS = [
    "login", "verify", "update", "secure", "account", "bank", "signin",
    "confirm", "password", "webscr", "invoice", "billing"
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"
}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    n = len(s)
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def _count_regex(pattern: str, s: str) -> int:
    return len(re.findall(pattern, s))


@dataclass(frozen=True)
class FeatureSpec:
    # Keep order stable; model depends on it
    names: tuple[str, ...] = (
        "url_len",
        "host_len",
        "path_len",
        "query_len",
        "num_dots",
        "num_digits",
        "num_special",
        "num_params",
        "has_ip_host",
        "uses_https",
        "has_at_symbol",
        "has_double_slash_in_path",
        "num_subdomains",
        "tld_len",
        "host_entropy",
        "path_entropy",
        "suspicious_token_count",
        "is_shortener",
    )


SPEC = FeatureSpec()


def extract_features(url: str) -> dict[str, float]:
    url = url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        # Treat missing scheme as http (common user input)
        url = "http://" + url

    parsed = urlparse(url)
    host = (parsed.netloc or "").lower()
    path = unquote(parsed.path or "")
    query = parsed.query or ""

    ext = tldextract.extract(host)
    registered = ".".join([p for p in [ext.domain, ext.suffix] if p])

    # Basic counts
    url_len = float(len(url))
    host_len = float(len(host))
    path_len = float(len(path))
    query_len = float(len(query))
    num_dots = float(host.count("."))
    num_digits = float(_count_regex(r"\d", url))
    num_special = float(_count_regex(r"[^A-Za-z0-9]", url))
    num_params = float(0 if not query else len(query.split("&")))

    uses_https = 1.0 if parsed.scheme == "https" else 0.0
    has_at_symbol = 1.0 if "@" in url else 0.0
    has_double_slash_in_path = 1.0 if "//" in (parsed.path or "") else 0.0

    # IP host check
    has_ip_host = 1.0 if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host.split(":")[0]) else 0.0

    # Subdomains
    subdomain_part = ext.subdomain
    num_subdomains = float(0 if not subdomain_part else len(subdomain_part.split(".")))

    tld_len = float(len(ext.suffix or ""))

    host_entropy = float(_shannon_entropy(host))
    path_entropy = float(_shannon_entropy(path))

    lowered = url.lower()
    suspicious_token_count = float(sum(1 for tok in SUSPICIOUS_TOKENS if tok in lowered))

    is_shortener = 1.0 if (registered in SHORTENER_DOMAINS) else 0.0

    feats = {
        "url_len": url_len,
        "host_len": host_len,
        "path_len": path_len,
        "query_len": query_len,
        "num_dots": num_dots,
        "num_digits": num_digits,
        "num_special": num_special,
        "num_params": num_params,
        "has_ip_host": has_ip_host,
        "uses_https": uses_https,
        "has_at_symbol": has_at_symbol,
        "has_double_slash_in_path": has_double_slash_in_path,
        "num_subdomains": num_subdomains,
        "tld_len": tld_len,
        "host_entropy": host_entropy,
        "path_entropy": path_entropy,
        "suspicious_token_count": suspicious_token_count,
        "is_shortener": is_shortener,
    }

    # Ensure spec completeness + order
    return {name: float(feats.get(name, 0.0)) for name in SPEC.names}


def vectorize(url: str) -> list[float]:
    f = extract_features(url)
    return [f[name] for name in SPEC.names]

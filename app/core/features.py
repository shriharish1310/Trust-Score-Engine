from __future__ import annotations
import math
import re
from dataclasses import dataclass
from urllib.parse import urlparse, unquote

import tldextract

from .content_features import extract_content_features, CONTENT_SPEC
from .infrastructure import INFRA_SPEC, extract_infra_features

SUSPICIOUS_TOKENS = [
    "login", "verify", "update", "secure", "account", "bank", "signin",
    "confirm", "password", "webscr", "invoice", "billing"
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"
}

COMMON_TLDS = {
    "com", "org", "net", "edu", "gov", "mil",
    "io", "ai", "co", "us", "uk", "in", "de", "fr", "jp", "ca", "au"
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
    names: tuple[str, ...] = (
        # existing
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

        # NEW: domain-leve
        "registered_domain_len",
        "domain_len",
        "subdomain_len",
        "num_hyphens_host",
        "num_digits_host",
        "is_punycode",
        "tld_in_top",

        # content + relationship
        *CONTENT_SPEC.names,

        # WHOIS age, DNS TTL, TLS certificate
        *INFRA_SPEC.names,

        # graph / metadata degrees
        "graph_ip_degree",
        "graph_asn_degree",
        "graph_ssl_issuer_degree",
        "graph_brand_degree",
    )


SPEC = FeatureSpec()


def extract_features(
    url: str,
    html: str | None = None,
    js_texts: list[str] | None = None,
    metadata: dict | None = None,
) -> dict[str, float]:
    url = url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
    except ValueError:
        # Malformed IPv6 / broken URL. Return zeros so training can continue.
        return {name: 0.0 for name in SPEC.names}
    host = (parsed.netloc or "").lower()
    path = unquote(parsed.path or "")
    query = parsed.query or ""

    try:
        ext = tldextract.extract(host)
    except Exception:
        ext = tldextract.extract("")
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

    # New Features
    registered_domain_len = float(len(registered))
    domain_len = float(len(ext.domain or ""))
    subdomain_len = float(len(ext.subdomain or ""))

    host_no_port = host.split(":")[0]
    num_hyphens_host = float(host_no_port.count("-"))
    num_digits_host = float(_count_regex(r"\d", host_no_port))

    is_punycode = 1.0 if "xn--" in host_no_port else 0.0

    tld = (ext.suffix or "").lower()
    tld_in_top = 1.0 if (tld in COMMON_TLDS) else 0.0


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

        "registered_domain_len": registered_domain_len,
        "domain_len": domain_len,
        "subdomain_len": subdomain_len,
        "num_hyphens_host": num_hyphens_host,
        "num_digits_host": num_digits_host,
        "is_punycode": is_punycode,
        "tld_in_top": tld_in_top,
    }

    meta = metadata or {}
    content_feats = extract_content_features(
        url,
        html=html,
        js_texts=js_texts,
        brand=str(meta.get("brand", "")) if meta.get("brand") is not None else None,
    )
    feats.update(content_feats)

    feats.update(extract_infra_features(meta))

    feats.update(
        {
            "graph_ip_degree": float(meta.get("ip_degree", 0.0)),
            "graph_asn_degree": float(meta.get("asn_degree", 0.0)),
            "graph_ssl_issuer_degree": float(meta.get("ssl_issuer_degree", 0.0)),
            "graph_brand_degree": float(meta.get("brand_degree", 0.0)),
        }
    )

    return {name: float(feats.get(name, 0.0)) for name in SPEC.names}


def vectorize(
    url: str,
    html: str | None = None,
    js_texts: list[str] | None = None,
    metadata: dict | None = None,
    feature_names: list[str] | None = None,
) -> list[float]:
    f = extract_features(url, html=html, js_texts=js_texts, metadata=metadata)
    names = feature_names or list(SPEC.names)
    return [f.get(name, 0.0) for name in names]

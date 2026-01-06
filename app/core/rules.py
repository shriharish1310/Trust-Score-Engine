from __future__ import annotations
from dataclasses import dataclass
from urllib.parse import urlparse

from .features import extract_features


@dataclass(frozen=True)
class RuleHit:
    code: str
    points: int
    message: str


def run_rules(url: str) -> list[RuleHit]:
    hits: list[RuleHit] = []
    feats = extract_features(url)
    parsed = urlparse(url if "://" in url else "http://" + url)

    if feats["has_ip_host"] == 1.0:
        hits.append(RuleHit("ip_host", 25, "URL uses a raw IP address as host (common in malicious links)."))

    if feats["has_at_symbol"] == 1.0:
        hits.append(RuleHit("at_symbol", 20, "URL contains '@' which can be used to mislead users."))

    if feats["url_len"] > 120:
        hits.append(RuleHit("very_long", 10, "URL is unusually long."))

    if feats["num_subdomains"] >= 3:
        hits.append(RuleHit("many_subdomains", 10, "URL has many subdomains (can be used for spoofing)."))

    if feats["suspicious_token_count"] >= 2:
        hits.append(RuleHit("suspicious_tokens", 15, "URL contains multiple suspicious keywords (login/verify/etc.)."))

    if parsed.scheme != "https":
        hits.append(RuleHit("no_https", 8, "URL is not using HTTPS."))

    return hits


def heuristic_risk(url: str) -> tuple[float, list[RuleHit]]:
    hits = run_rules(url)
    points = sum(h.points for h in hits)
    # Clamp into [0,1]
    risk = min(1.0, points / 100.0)
    return risk, hits

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from .features import extract_features


@dataclass(frozen=True)
class RuleHit:
    code: str
    points: int
    message: str


# High-confidence malware-ish file endings often seen in URLhaus-style URLs
SUSPICIOUS_EXTS = (
    ".sh", ".exe", ".ps1", ".bat", ".cmd", ".js", ".vbs", ".scr", ".msi",
    ".apk", ".jar", ".zip", ".rar", ".7z"
)

# Ports that are not "wrong", but commonly seen in suspicious hosting patterns
SUSPICIOUS_PORTS = {81, 82, 83, 444, 8000, 8080, 8081, 8888, 1337, 2082, 2083, 2095, 2096}


def _path_has_suspicious_extension(path: str) -> bool:
    p = (path or "").lower()
    return any(p.endswith(ext) for ext in SUSPICIOUS_EXTS)


def run_rules(url: str) -> list[RuleHit]:
    hits: list[RuleHit] = []
    feats = extract_features(url)

    parsed = urlparse(url if "://" in url else "http://" + url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    port = parsed.port

    # 1) IP as host (strong indicator)
    if feats.get("has_ip_host", 0.0) == 1.0:
        hits.append(
            RuleHit("ip_host", 55, "URL uses a raw IP address as host (strong malicious indicator).")
        )

    # 2) '@' symbol (deception)
    if feats.get("has_at_symbol", 0.0) == 1.0:
        hits.append(
            RuleHit("at_symbol", 25, "URL contains '@' which can be used to mislead users.")
        )

    # 3) Not HTTPS (moderate risk; lots of benign sites still use http, but it's weaker)
    if parsed.scheme.lower() != "https":
        hits.append(
            RuleHit("no_https", 15, "URL is not using HTTPS.")
        )

    # 4) Very long URL (weak/moderate)
    if feats.get("url_len", 0.0) > 120:
        hits.append(
            RuleHit("very_long", 12, "URL is unusually long.")
        )

    # 5) Many subdomains (spoofing)
    if feats.get("num_subdomains", 0.0) >= 3:
        hits.append(
            RuleHit("many_subdomains", 15, "URL has many subdomains (can be used for spoofing).")
        )

    # 6) Suspicious tokens (login/verify/etc.)
    if feats.get("suspicious_token_count", 0.0) >= 2:
        hits.append(
            RuleHit("suspicious_tokens", 20, "URL contains multiple suspicious keywords (login/verify/etc.).")
        )

    # 7) Suspicious file extension in path (strong in malware-delivery URLs)
    if _path_has_suspicious_extension(path):
        hits.append(
            RuleHit("suspicious_ext", 35, f"URL path ends with a suspicious file type (e.g., {SUSPICIOUS_EXTS[0]}).")
        )

    # 8) Suspicious port (moderate)
    if port is not None and port in SUSPICIOUS_PORTS:
        hits.append(
            RuleHit("suspicious_port", 18, f"URL uses an uncommon port ({port}), often seen in suspicious hosting.")
        )

    # 9) "www." abuse is not necessarily bad, but weird host patterns can be flagged later
    # (left out intentionally to avoid false positives)

    return hits


def heuristic_risk(url: str) -> tuple[float, list[RuleHit]]:
    hits = run_rules(url)
    points = sum(h.points for h in hits)

    # Convert points -> risk. Using /100 makes "100 points = max risk".
    # With strengthened rules, clearly malicious URLs will exceed 60 points.
    risk = min(1.0, points / 100.0)
    return risk, hits

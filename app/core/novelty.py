from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from difflib import SequenceMatcher
from threading import Lock
from urllib.parse import urlparse

import tldextract


KNOWN_BRANDS = (
    "google",
    "microsoft",
    "apple",
    "amazon",
    "paypal",
    "netflix",
    "instagram",
    "facebook",
    "linkedin",
    "github",
    "bankofamerica",
    "chase",
    "wellsfargo",
)


def _registered_domain(url: str) -> str:
    u = url if "://" in url else "http://" + url
    host = (urlparse(u).hostname or "").lower()
    ext = tldextract.extract(host)
    return ".".join([p for p in (ext.domain, ext.suffix) if p])


def _domain_label(url: str) -> str:
    u = url if "://" in url else "http://" + url
    host = (urlparse(u).hostname or "").lower()
    ext = tldextract.extract(host)
    return (ext.domain or "").lower()


def homograph_brand_risk(url: str) -> tuple[float, str]:
    """
    Risk in [0, 1] based on brand-like hostnames and potential homograph signals.
    """
    domain = _domain_label(url)
    if not domain:
        return 0.0, "No hostname label available for homograph analysis."

    punycode = "xn--" in domain

    best_brand = ""
    best_sim = 0.0
    for b in KNOWN_BRANDS:
        sim = SequenceMatcher(None, domain, b).ratio()
        if sim > best_sim:
            best_sim = sim
            best_brand = b

    if punycode and best_sim >= 0.55:
        return min(1.0, 0.65 + (best_sim - 0.55)), (
            f"Punycode-like hostname with brand similarity to '{best_brand}' (sim={best_sim:.2f})."
        )
    if best_sim >= 0.82 and domain != best_brand:
        return min(1.0, 0.35 + (best_sim - 0.82) * 2.0), (
            f"Hostname is visually similar to known brand '{best_brand}' (sim={best_sim:.2f})."
        )

    return 0.0, "No suspicious homograph/brand-impersonation pattern detected."


@dataclass
class DriftRecord:
    trust_score: int
    updated_at: str


_DRIFT_STATE: dict[str, DriftRecord] = {}
_DRIFT_LOCK = Lock()


def temporal_drift_risk(url: str, trust_score: int) -> tuple[float, str]:
    """
    Compare trust score to previously seen score for the same registered domain.
    """
    rd = _registered_domain(url)
    if not rd:
        return 0.0, "No registered domain available for temporal drift analysis."

    now = datetime.now(timezone.utc).isoformat()
    with _DRIFT_LOCK:
        prev = _DRIFT_STATE.get(rd)
        _DRIFT_STATE[rd] = DriftRecord(trust_score=trust_score, updated_at=now)

    if prev is None:
        return 0.0, "First observation for domain; temporal drift baseline created."

    delta = prev.trust_score - trust_score
    if delta <= 5:
        return 0.0, f"Temporal drift stable (delta_trust={delta})."
    if delta <= 20:
        return 0.2, f"Moderate trust deterioration since last observation (delta_trust={delta})."
    if delta <= 40:
        return 0.45, f"Significant trust deterioration since last observation (delta_trust={delta})."
    return 0.7, f"Severe trust deterioration since last observation (delta_trust={delta})."


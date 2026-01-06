from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse, urlunparse

import joblib
import numpy as np

from .features import vectorize, SPEC
from .rules import heuristic_risk

ARTIFACT_DIR = Path(__file__).resolve().parents[2] / "ml" / "artifacts"
MODEL_PATH = ARTIFACT_DIR / "model.joblib"


def canonicalize_url(url: str) -> str:
    """
    Normalize URL so syntactic variants score consistently.
    Goals (prototype-safe):
      - lowercase scheme + host
      - strip leading 'www.'
      - remove default ports (:80 for http, :443 for https)
      - remove trailing slash (except keep '/' for empty path)
      - drop params/query/fragment for now (optional; keep later if you want)
    """
    url = (url or "").strip()
    if not url:
        return url

    p = urlparse(url)

    scheme = (p.scheme or "http").lower()

    host = (p.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]

    # preserve non-default ports
    port = p.port
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    if port is None or default_port:
        netloc = host
    else:
        netloc = f"{host}:{port}"

    # normalize path
    path = p.path or "/"
    if path != "/":
        path = path.rstrip("/")
        if not path:
            path = "/"

    # For canonical scoring, drop query/fragment to reduce noisy variants
    # (You can flip this later if query-based phishing is important.)
    query = ""
    fragment = ""

    return urlunparse((scheme, netloc, path, "", query, fragment))


class URLTrustModel:
    def __init__(self) -> None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"Model not found at {MODEL_PATH}. Train it first: python -m ml.train"
            )
        self.model = joblib.load(MODEL_PATH)

    def predict_proba_malicious(self, url: str) -> float:
        x = np.array([vectorize(url)], dtype=float)
        # binary classifier expects [p(0), p(1)]
        proba = self.model.predict_proba(x)[0, 1]
        return float(proba)

    def score(self, url: str) -> dict:
        url_input = url
        url = canonicalize_url(url)

        ml_risk = self.predict_proba_malicious(url)  # 0..1
        heur_risk, hits = heuristic_risk(url)

        # Weighted blend: tune later
        final_risk = 0.30 * ml_risk + 0.70 * heur_risk
        final_risk = max(0.0, min(1.0, final_risk))

        trust_score = int(round(100 * (1.0 - final_risk)))

        if trust_score >= 70:
            verdict = "SAFE"
        elif trust_score >= 40:
            verdict = "SUSPICIOUS"
        else:
            verdict = "DANGEROUS"

        reasons = [{"code": h.code, "points": h.points, "message": h.message} for h in hits]

        return {
            "url_input": url_input,  # what the user/tab provided
            "url": url,              # canonical URL that was actually scored
            "trust_score": trust_score,
            "verdict": verdict,
            "risk": {
                "final": final_risk,
                "ml": ml_risk,
                "heuristic": heur_risk,
            },
            "feature_names": list(SPEC.names),
            "reasons": reasons,
        }

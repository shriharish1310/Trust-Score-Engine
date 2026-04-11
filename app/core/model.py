from __future__ import annotations

from pathlib import Path
import json
from urllib.parse import urlparse, urlunparse

import joblib
import numpy as np
import tldextract

from ..config import high_trust_domain_set, settings
from .content_fetch import fetch_content
from .features import vectorize, SPEC
from .infrastructure import fetch_infrastructure
from .rules import heuristic_risk

ARTIFACT_DIR = Path(__file__).resolve().parents[2] / "ml" / "artifacts"
MODEL_PATH = ARTIFACT_DIR / "model.joblib"
SPEC_PATH = ARTIFACT_DIR / "feature_spec.json"

LABELS = ["benign", "phishing"]
BENIGN_LABEL = "benign"
PHISHING_LABEL = "phishing"


def canonicalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return url

    if "://" not in url:
        url = "http://" + url

    p = urlparse(url)

    scheme = (p.scheme or "http").lower()

    host = (p.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]

    port = p.port
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    if port is None or default_port:
        netloc = host
    else:
        netloc = f"{host}:{port}"

    path = p.path or "/"
    if path != "/":
        path = path.rstrip("/")
        if not path:
            path = "/"

    query = ""
    fragment = ""

    return urlunparse((scheme, netloc, path, "", query, fragment))


def _registered_domain(host: str) -> str:
    h = (host or "").strip().lower()
    if h.startswith("["):
        return ""
    try:
        ext = tldextract.extract(h)
    except Exception:
        return ""
    return ".".join([p for p in [ext.domain, ext.suffix] if p])


def is_high_trust_url(url: str) -> bool:
    """True if the URL's hostname registered domain is on the high-trust allowlist."""
    if not settings.high_trust_allowlist:
        return False
    try:
        p = urlparse(url if "://" in url else "http://" + url)
    except ValueError:
        return False
    host = (p.hostname or "").lower()
    if not host or host.startswith("["):
        return False
    rd = _registered_domain(host)
    if not rd:
        return False
    return rd in high_trust_domain_set()


class URLTrustModel:
    def __init__(self) -> None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"Model not found at {MODEL_PATH}. Train it first: python -m ml.train"
            )
        self.model = joblib.load(MODEL_PATH)
        self.feature_names = list(SPEC.names)
        if SPEC_PATH.exists():
            try:
                with open(SPEC_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict) and isinstance(data.get("feature_names"), list):
                    self.feature_names = data["feature_names"]
            except (OSError, json.JSONDecodeError):
                pass
        n_features = getattr(self.model, "n_features_", None)
        if isinstance(n_features, int) and n_features != len(self.feature_names):
            self.feature_names = list(SPEC.names)[:n_features]

    def predict_proba(
        self,
        url: str,
        html: str | None = None,
        js_texts: list[str] | None = None,
        metadata: dict | None = None,
    ) -> dict[str, float]:
        x = np.array(
            [vectorize(url, html=html, js_texts=js_texts, metadata=metadata, feature_names=self.feature_names)],
            dtype=float,
        )
        proba = self.model.predict_proba(x)[0]
        out = {}
        for i, name in enumerate(LABELS):
            out[name] = float(proba[i]) if i < len(proba) else 0.0
        return out

    def score(self, url: str) -> dict:
        url_input = url
        url = canonicalize_url(url)

        html = None
        js_texts: list[str] = []
        feature_url = url
        if settings.fetch_content:
            fetched = fetch_content(
                url,
                timeout=settings.request_timeout,
                max_html_bytes=settings.max_html_bytes,
                fetch_external_js=settings.fetch_external_js,
                max_js_files=settings.max_js_files,
                max_js_bytes=settings.max_js_bytes,
            )
            html = fetched.html
            js_texts = fetched.js_texts
            if fetched.final_url:
                feature_url = fetched.final_url

        metadata: dict = {}
        if settings.fetch_infra:
            try:
                ph = urlparse(feature_url).hostname
                if ph:
                    metadata["infra"] = fetch_infrastructure(
                        ph,
                        timeout=settings.request_timeout,
                    )
            except Exception:
                pass

        probs = self.predict_proba(
            feature_url,
            html=html,
            js_texts=js_texts,
            metadata=metadata or None,
        )
        predicted_class = max(probs, key=probs.get)

        # ML risk: phishing probability
        ml_risk = float(probs.get(PHISHING_LABEL, 0.0))

        heur_risk, hits = heuristic_risk(url)

        # keep your blend; tune later
        final_risk = 0.85 * ml_risk + 0.15 * heur_risk

        final_risk = max(0.0, min(1.0, final_risk))

        trust_score = int(round(100 * (1.0 - final_risk)))

        if trust_score >= 70:
            verdict = "SAFE"
        elif trust_score >= 40:
            verdict = "SUSPICIOUS"
        else:
            verdict = "DANGEROUS"

        allowlisted = is_high_trust_url(feature_url)
        if allowlisted:
            cap = max(1, min(100, settings.high_trust_score))
            trust_score = cap
            final_risk = 1.0 - (cap / 100.0)
            verdict = "SAFE"

        reasons = [{"code": h.code, "points": h.points, "message": h.message} for h in hits]
        if allowlisted:
            reasons.insert(
                0,
                {
                    "code": "high_trust_allowlist",
                    "points": 0,
                    "message": "Registered domain matches the built-in high-trust allowlist (major provider).",
                },
            )

        return {
            "url_input": url_input,
            "url": url,
            "trust_score": trust_score,
            "verdict": verdict,
            "predicted_class": predicted_class,
            "class_probabilities": probs,
            "risk": {
                "final": final_risk,
                "ml": ml_risk,
                "heuristic": heur_risk,
                "high_trust_allowlist": 1.0 if allowlisted else 0.0,
            },
            "feature_names": list(self.feature_names),
            "reasons": reasons,
        }

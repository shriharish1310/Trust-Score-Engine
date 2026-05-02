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
from .reputation import dataset_reputation
from .rules import heuristic_risk

ARTIFACT_DIR = Path(__file__).resolve().parents[2] / "ml" / "artifacts"
MODEL_PATH = ARTIFACT_DIR / "model.joblib"
SPEC_PATH = ARTIFACT_DIR / "feature_spec.json"

LABELS = ["benign", "phishing"]
BENIGN_LABEL = "benign"
PHISHING_LABEL = "phishing"


def _clamp_risk(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _verdict_from_risk(risk: float) -> tuple[int, str]:
    trust_score = int(round(100 * (1.0 - _clamp_risk(risk))))
    if trust_score >= 65:
        return trust_score, "SAFE"
    if trust_score >= 40:
        return trust_score, "SUSPICIOUS"
    return trust_score, "DANGEROUS"


def _hostname(url: str) -> str:
    try:
        return (urlparse(url if "://" in url else "http://" + url).hostname or "").lower()
    except ValueError:
        return ""


def _equal_weight_average(layers: list[dict]) -> float:
    active = [layer for layer in layers if layer.get("included")]
    if not active:
        return 0.5
    return _clamp_risk(sum(float(layer["risk"]) for layer in active) / len(active))


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

    path = p.path or ""
    if path and path != "/":
        path = path.rstrip("/")
        if not path:
            path = ""
    elif path == "/":
        path = ""

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
                feature_url = canonicalize_url(fetched.final_url)

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

        raw_probs = self.predict_proba(
            feature_url,
            html=html,
            js_texts=js_texts,
            metadata=metadata or None,
        )
        probs = dict(raw_probs)
        predicted_class = max(probs, key=probs.get)

        # ML risk: phishing probability
        ml_risk = float(probs.get(PHISHING_LABEL, 0.0))
        raw_ml_risk = ml_risk

        heur_risk, hits = heuristic_risk(url)
        reputation = dataset_reputation(feature_url)

        allowlisted = is_high_trust_url(feature_url)
        host = _hostname(feature_url)
        rd = str(reputation.get("registered_domain") or "")
        benign_domain_reputation_applies = (
            reputation.get("known_benign_domain") is True
            and reputation.get("exact_malicious") is False
            and bool(rd)
            and host == rd
        )
        dataset_malicious_match = reputation.get("exact_malicious") is True

        evidence_layers = [
            {
                "name": "lexical_ml",
                "risk": ml_risk,
                "included": True,
                "detail": "LightGBM lexical URL classifier risk.",
            },
            {
                "name": "heuristic_rules",
                "risk": heur_risk,
                "included": True,
                "detail": "Rule-based URL risk.",
            },
            {
                "name": "dataset_reputation",
                "risk": 1.0 if dataset_malicious_match else 0.0,
                "included": dataset_malicious_match or benign_domain_reputation_applies,
                "detail": str(reputation.get("detail", "No local reputation evidence.")),
            },
            {
                "name": "high_trust_allowlist",
                "risk": 0.0,
                "included": allowlisted,
                "detail": "Registered domain matched built-in high-trust allowlist.",
            },
        ]

        final_risk = _equal_weight_average(evidence_layers)
        trust_score, verdict = _verdict_from_risk(final_risk)
        predicted_class = PHISHING_LABEL if final_risk >= 0.5 else BENIGN_LABEL
        probs = {
            BENIGN_LABEL: 1.0 - final_risk,
            PHISHING_LABEL: final_risk,
        }

        reasons = [{"code": h.code, "points": h.points, "message": h.message} for h in hits]
        if dataset_malicious_match:
            reasons.insert(
                0,
                {
                    "code": "dataset_malicious_url",
                    "points": 95,
                    "message": "Exact URL matches the local malicious URL dataset.",
                },
            )
        elif benign_domain_reputation_applies:
            reasons.insert(
                0,
                {
                    "code": "dataset_benign_domain",
                    "points": 0,
                    "message": "Registered domain appears in the local Tranco benign-domain dataset.",
                },
            )
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
                "raw_ml": raw_ml_risk,
                "heuristic": heur_risk,
                "dataset_reputation": float(reputation.get("risk", 0.35)),
                "dataset_benign_domain": 1.0 if benign_domain_reputation_applies else 0.0,
                "dataset_malicious_url": 1.0 if reputation.get("exact_malicious") else 0.0,
                "high_trust_allowlist": 1.0 if allowlisted else 0.0,
            },
            "aggregation": {
                "method": "equal_weight_available_layers",
                "layers": evidence_layers,
            },
            "reputation": reputation,
            "feature_names": list(self.feature_names),
            "reasons": reasons,
        }

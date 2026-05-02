from __future__ import annotations

from dataclasses import dataclass

from ..config import settings
from .model import URLTrustModel
from .novelty import homograph_brand_risk, temporal_drift_risk


@dataclass(frozen=True)
class Signal:
    name: str
    risk: float
    score: int
    detail: str


def _score_from_risk(risk: float) -> int:
    r = max(0.0, min(1.0, float(risk)))
    return int(round(100 * (1.0 - r)))


def _equal_weight_average(risks: list[float]) -> float:
    if not risks:
        return 0.5
    return max(0.0, min(1.0, sum(float(r) for r in risks) / len(risks)))


def scan_url(model: URLTrustModel, url: str) -> dict:
    base = model.score(url)

    ml_risk = float(base.get("risk", {}).get("ml", 0.0))
    heur_risk = float(base.get("risk", {}).get("heuristic", 0.0))
    reputation_risk = float(base.get("risk", {}).get("dataset_reputation", 0.35))
    allowlisted = float(base.get("risk", {}).get("high_trust_allowlist", 0.0)) == 1.0
    reputation = base.get("reputation", {})
    aggregation_layers = [
        layer
        for layer in base.get("aggregation", {}).get("layers", [])
        if isinstance(layer, dict) and layer.get("included")
    ]
    aggregation_by_name = {str(layer.get("name")): layer for layer in aggregation_layers}
    displayed_reputation_risk = float(
        aggregation_by_name.get("dataset_reputation", {}).get("risk", reputation_risk)
    )
    heuristic_reason_count = sum(
        1
        for reason in base.get("reasons", [])
        if isinstance(reason, dict)
        and reason.get("code")
        not in {"high_trust_allowlist", "dataset_benign_domain", "dataset_malicious_url"}
    )

    signals: list[Signal] = [
        Signal(
            name="lexical_ml",
            risk=ml_risk,
            score=_score_from_risk(ml_risk),
            detail="LightGBM phishing probability from extracted URL/content/infra features.",
        ),
        Signal(
            name="heuristic_rules",
            risk=heur_risk,
            score=_score_from_risk(heur_risk),
            detail=f"Triggered {heuristic_reason_count} heuristic rule hits.",
        ),
        Signal(
            name="dataset_reputation",
            risk=displayed_reputation_risk,
            score=_score_from_risk(displayed_reputation_risk),
            detail=str(reputation.get("detail", "Local dataset reputation was not available.")),
        ),
    ]

    if allowlisted:
        signals.append(
            Signal(
                name="high_trust_allowlist",
                risk=0.0,
                score=100,
                detail="Registered domain matched built-in high-trust allowlist.",
            )
        )

    homo_risk, homo_msg = homograph_brand_risk(base.get("url", url))
    signals.append(
        Signal(
            name="homograph_brand",
            risk=homo_risk,
            score=_score_from_risk(homo_risk),
            detail=homo_msg,
        )
    )

    drift_risk, drift_msg = temporal_drift_risk(base.get("url", url), int(base.get("trust_score", 0)))
    signals.append(
        Signal(
            name="temporal_drift",
            risk=drift_risk,
            score=_score_from_risk(drift_risk),
            detail=drift_msg,
        )
    )

    base_risk = float(base.get("risk", {}).get("final", 0.0))
    final_layers = [base_risk]
    if homo_risk > 0:
        final_layers.append(homo_risk)
    if drift_risk > 0:
        final_layers.append(drift_risk)
    augmented_risk = _equal_weight_average(final_layers)
    trust_score = _score_from_risk(augmented_risk)
    if trust_score >= 65:
        verdict = "SAFE"
    elif trust_score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "DANGEROUS"

    return {
        "product_name": settings.app_name,
        "url_input": base.get("url_input", url),
        "url": base.get("url", url),
        "trust_score": trust_score,
        "verdict": verdict,
        "predicted_class": base.get("predicted_class"),
        "class_probabilities": base.get("class_probabilities", {}),
        "risk": {
            "final": augmented_risk,
            "base": base_risk,
            "ml": ml_risk,
            "raw_ml": float(base.get("risk", {}).get("raw_ml", ml_risk)),
            "heuristic": heur_risk,
            "dataset_reputation": reputation_risk,
            "dataset_benign_domain": float(base.get("risk", {}).get("dataset_benign_domain", 0.0)),
            "dataset_malicious_url": float(base.get("risk", {}).get("dataset_malicious_url", 0.0)),
            "homograph_brand": homo_risk,
            "temporal_drift": drift_risk,
            "high_trust_allowlist": 1.0 if allowlisted else 0.0,
        },
        "reputation": reputation,
        "signals": [
            {"name": s.name, "risk": s.risk, "score": s.score, "detail": s.detail}
            for s in signals
        ],
        "reasons": base.get("reasons", []),
        "feature_names": base.get("feature_names", []),
    }


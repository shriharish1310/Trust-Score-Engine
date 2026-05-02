from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.model import is_high_trust_url
from app.main import app


def test_is_high_trust_google_variants():
    assert is_high_trust_url("https://www.google.com/")
    assert is_high_trust_url("https://maps.google.com/foo")
    assert is_high_trust_url("google.com")


def test_is_high_trust_not_evil_typos():
    assert not is_high_trust_url("https://google.com.evil.com/")
    assert not is_high_trust_url("https://example.com/")


def test_score_google_is_safe_with_startup():
    with TestClient(app) as client:
        r = client.post("/score", json={"url": "https://www.google.com/search?q=test"})
    assert r.status_code == 200
    data = r.json()
    assert data["verdict"] == "SAFE"
    assert data["trust_score"] >= 70
    assert any(x.get("code") == "high_trust_allowlist" for x in data.get("reasons", []))
    assert data.get("risk", {}).get("high_trust_allowlist") == 1.0


def test_google_root_with_trailing_slash_does_not_flip_raw_model_risk():
    with TestClient(app) as client:
        r = client.post("/score", json={"url": "https://google.com/"})
    assert r.status_code == 200
    data = r.json()
    assert data["url"] == "https://google.com"
    assert data["predicted_class"] == "benign"
    assert data["class_probabilities"]["benign"] >= 0.9
    assert data["risk"]["raw_ml"] < 0.01


def test_known_benign_dataset_domain_can_reduce_false_positive():
    with TestClient(app) as client:
        r = client.post("/score", json={"url": "https://www.chess.com/home"})
    assert r.status_code == 200
    data = r.json()
    assert data["verdict"] == "SAFE"
    assert data["predicted_class"] == "benign"
    assert data["risk"]["dataset_benign_domain"] == 1.0
    assert any(x.get("code") == "dataset_benign_domain" for x in data.get("reasons", []))


def test_known_benign_registered_domain_does_not_override_heuristic_risk():
    with TestClient(app) as client:
        r = client.post(
            "/score",
            json={"url": "https://paypal-login-verify.example.com/account"},
        )
    assert r.status_code == 200
    data = r.json()
    assert data["verdict"] != "SAFE"
    assert not any(x.get("code") == "dataset_benign_domain" for x in data.get("reasons", []))

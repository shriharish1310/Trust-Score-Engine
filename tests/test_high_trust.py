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
    assert data["trust_score"] >= 90
    assert any(x.get("code") == "high_trust_allowlist" for x in data.get("reasons", []))
    assert data.get("risk", {}).get("high_trust_allowlist") == 1.0

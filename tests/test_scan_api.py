from __future__ import annotations

import json

from fastapi.testclient import TestClient

from app.config import settings
from app.main import app


def test_scan_stream_returns_signal_events_and_complete_result():
    with TestClient(app) as client:
        response = client.post("/scan", json={"url": "https://example.com"})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-ndjson")

    events = [json.loads(line) for line in response.text.splitlines() if line.strip()]
    event_names = [event["event"] for event in events]

    assert event_names[0] == "scan_started"
    assert "signal_result" in event_names
    assert event_names[-1] == "scan_complete"

    result = events[-1]["result"]
    assert result["product_name"] == settings.app_name
    assert isinstance(result["signals"], list)
    assert {signal["name"] for signal in result["signals"]} >= {
        "lexical_ml",
        "heuristic_rules",
        "homograph_brand",
        "temporal_drift",
    }
    assert 0 <= result["trust_score"] <= 100


def test_scan_batch_validates_and_returns_results():
    with TestClient(app) as client:
        response = client.post(
            "/scan/batch",
            json={"urls": ["https://example.com", "https://github.com"]},
        )
        bad_response = client.post("/scan/batch", json={"urls": []})

    assert response.status_code == 200
    data = response.json()
    assert data["product_name"] == settings.app_name
    assert data["count"] == 2
    assert len(data["results"]) == 2
    assert all("signals" in result for result in data["results"])

    assert bad_response.status_code == 400


def test_scrutinix_analyze_alias_streams_type_events():
    with TestClient(app) as client:
        response = client.post("/api/analyze", json={"url": "example.com"})

    assert response.status_code == 200
    events = [json.loads(line) for line in response.text.splitlines() if line.strip()]
    event_types = [event["type"] for event in events]

    assert event_types[0] == "scan_started"
    assert "signal_result" in event_types
    assert event_types[-1] == "scan_complete"
    assert events[-1]["result"]["productName"] == "URL Trust Scorer"
    assert events[-1]["result"]["raw"]["product_name"] == "URL Trust Scorer"


def test_json_result_endpoints_return_single_parseable_objects():
    with TestClient(app) as client:
        native_response = client.post("/scan/result", json={"url": "example.com"})
        scrutinix_response = client.post("/api/analyze/result", json={"url": "example.com"})
        scrutinix_batch_response = client.post(
            "/api/analyze/batch/result",
            json={"urls": ["example.com", "github.com"]},
        )

    assert native_response.status_code == 200
    native = native_response.json()
    assert native["product_name"] == settings.app_name
    assert "signals" in native
    assert 0 <= native["trust_score"] <= 100

    assert scrutinix_response.status_code == 200
    scrutinix = scrutinix_response.json()
    assert scrutinix["productName"] == settings.app_name
    assert "raw" in scrutinix
    assert "signals" in scrutinix

    assert scrutinix_batch_response.status_code == 200
    scrutinix_batch = scrutinix_batch_response.json()
    assert scrutinix_batch["productName"] == settings.app_name
    assert scrutinix_batch["count"] == 2
    assert len(scrutinix_batch["results"]) == 2


def test_openapi_documents_streaming_endpoints_as_ndjson():
    with TestClient(app) as client:
        spec = client.get("/openapi.json").json()

    scan_content = spec["paths"]["/scan"]["post"]["responses"]["200"]["content"]
    analyze_content = spec["paths"]["/api/analyze"]["post"]["responses"]["200"]["content"]
    analyze_batch_content = spec["paths"]["/api/analyze/batch"]["post"]["responses"]["200"]["content"]
    assert "application/x-ndjson" in scan_content
    assert "application/x-ndjson" in analyze_content
    assert "application/x-ndjson" in analyze_batch_content


def test_scrutinix_batch_alias_streams_progress_events():
    with TestClient(app) as client:
        response = client.post(
            "/api/analyze/batch",
            json={"urls": ["example.com", "github.com"]},
        )

    assert response.status_code == 200
    events = [json.loads(line) for line in response.text.splitlines() if line.strip()]
    event_types = [event["type"] for event in events]

    assert event_types[0] == "batch_started"
    assert event_types.count("url_started") == 2
    assert event_types.count("url_complete") == 2
    assert event_types[-1] == "batch_complete"
    assert len(events[-1]["results"]) == 2

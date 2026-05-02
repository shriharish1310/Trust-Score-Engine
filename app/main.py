from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Iterable
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from .config import settings
from .core.scan_engine import scan_url
from .schemas import ScoreRequest, ScoreResponse
from .core.model import URLTrustModel

app = FastAPI(title=settings.app_name, version="0.2")

# Allow Chrome extension (and local tools) to call the API during prototype stage
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # prototype: open CORS. Later: restrict to chrome-extension://<id>
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_model: URLTrustModel | None = None  # global variable that later becomes the model instance


@app.on_event("startup")
def load_model() -> None:
    global _model
    _model = URLTrustModel()  # create model instance once at server startup


# Check if server is running (sanity check)
@app.get("/health")
def health():
    return {"ok": True}


@app.get("/")
def root():
    return {
        "product": settings.app_name,
        "ok": True,
        "docs": "/docs",
        "endpoints": {
            "health": "GET /health",
            "legacy_score": "POST /score",
            "native_scan_stream": "POST /scan",
            "native_scan_json": "POST /scan/result",
            "native_batch": "POST /scan/batch",
            "scrutinix_scan_stream": "POST /api/analyze",
            "scrutinix_scan_json": "POST /api/analyze/result",
            "scrutinix_batch": "POST /api/analyze/batch",
        },
    }


@app.post("/score", response_model=ScoreResponse)
def score(req: ScoreRequest):
    if _model is None:
        raise HTTPException(status_code=500, detail="Model not loaded.")
    return _model.score(req.url)


def _scan_events(result: dict) -> Iterable[str]:
    started = {
        "event": "scan_started",
        "product": result.get("product_name", settings.app_name),
        "url": result.get("url"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    yield json.dumps(started) + "\n"

    for signal in result.get("signals", []):
        yield json.dumps({"event": "signal_result", "signal": signal}) + "\n"

    yield json.dumps({"event": "scan_complete", "result": result}) + "\n"


def _normalize_url_input(raw_url: str) -> str:
    value = str(raw_url or "").strip()
    if not value:
        raise HTTPException(status_code=400, detail="Request body must include a string url.")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Enter a valid http or https URL.")
    return value


def _scrutinix_signal_event(signal: dict) -> dict:
    return {
        "type": "signal_result",
        "name": signal.get("name", "unknown"),
        "result": {
            "status": "success",
            "data": signal,
            "error": None,
            "durationMs": 0,
        },
    }


def _scrutinix_result(result: dict, scan_id: str, started_at: str) -> dict:
    completed_at = datetime.now(timezone.utc).isoformat()
    verdict_map = {
        "SAFE": "safe",
        "SUSPICIOUS": "suspicious",
        "DANGEROUS": "malicious",
    }
    verdict = verdict_map.get(str(result.get("verdict", "")).upper(), "error")
    risk_score = int(round(float(result.get("risk", {}).get("final", 0.0)) * 100))
    reasons = [r.get("message") or r.get("reason") or str(r) for r in result.get("reasons", [])]
    if not reasons:
        reasons = [s.get("detail", "") for s in result.get("signals", []) if s.get("risk", 0) > 0]
    if not reasons:
        reasons = ["No direct malicious indicators were found in the completed signals."]

    confidence = 0.9 if verdict == "safe" else 0.72
    if result.get("risk", {}).get("high_trust_allowlist") == 1.0:
        confidence = 0.95

    return {
        "id": scan_id,
        "url": result.get("url"),
        "verdict": verdict,
        "trustScore": result.get("trust_score"),
        "productName": result.get("product_name", settings.app_name),
        "raw": result,
        "signals": {
            signal.get("name", f"signal_{idx}"): {
                "status": "success",
                "data": signal,
                "error": None,
                "durationMs": 0,
            }
            for idx, signal in enumerate(result.get("signals", []))
        },
        "threatInfo": {
            "verdict": verdict,
            "confidence": confidence,
            "confidenceLabel": "high" if confidence >= 0.85 else "moderate",
            "confidenceReasons": [
                f"{len(result.get('signals', []))} local signals completed.",
                "External reputation providers are not configured in this FastAPI build.",
            ],
            "hasPositiveEvidence": verdict != "safe",
            "score": risk_score,
            "summary": (
                "No strong malicious indicators were found across the local signals."
                if verdict == "safe"
                else f"{verdict.title()} risk based on local model and heuristic signals."
            ),
            "categories": [
                name
                for name, value in result.get("risk", {}).items()
                if isinstance(value, (int, float)) and value > 0 and name != "final"
            ],
            "reasons": reasons,
            "recommendations": (
                [
                    "Continue normal caution for unfamiliar links.",
                    "Avoid entering credentials if the page or sender context looks unusual.",
                ]
                if verdict == "safe"
                else [
                    "Do not enter credentials, payment details, or MFA codes.",
                    "Open only in an isolated profile or sandbox if inspection is required.",
                ]
            ),
            "limitations": [
                "This local build does not include VirusTotal or Google Safe Browsing API keys.",
            ],
        },
        "metadata": {
            "scanId": scan_id,
            "startedAt": started_at,
            "completedAt": completed_at,
            "cacheHit": False,
            "partialFailure": False,
            "signalCount": len(result.get("signals", [])),
            "durationMs": int(
                (
                    datetime.fromisoformat(completed_at)
                    - datetime.fromisoformat(started_at)
                ).total_seconds()
                * 1000
            ),
        },
    }


def _analyze_events(url: str) -> Iterable[str]:
    if _model is None:
        raise HTTPException(status_code=500, detail="Model not loaded.")

    normalized = _normalize_url_input(url)
    scan_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()
    result = scan_url(_model, normalized)

    yield json.dumps(
        {
            "type": "scan_started",
            "scanId": scan_id,
            "url": result.get("url", normalized),
            "cached": False,
            "startedAt": started_at,
        }
    ) + "\n"

    for signal in result.get("signals", []):
        yield json.dumps(_scrutinix_signal_event(signal)) + "\n"

    yield json.dumps(
        {
            "type": "scan_complete",
            "result": _scrutinix_result(result, scan_id, started_at),
        }
    ) + "\n"


_NDJSON_RESPONSE = {
    200: {
        "description": "Streaming newline-delimited JSON events. Use the matching /result endpoint for a single JSON object.",
        "content": {
            "application/x-ndjson": {
                "schema": {
                    "type": "string",
                    "example": (
                        '{"event":"scan_started","url":"https://example.com"}\n'
                        '{"event":"signal_result","signal":{"name":"lexical_ml","risk":0.2}}\n'
                        '{"event":"scan_complete","result":{"verdict":"SAFE","trust_score":80}}\n'
                    ),
                }
            }
        },
    }
}


@app.post("/scan", response_class=StreamingResponse, responses=_NDJSON_RESPONSE)
def scan(req: ScoreRequest):
    if _model is None:
        raise HTTPException(status_code=500, detail="Model not loaded.")
    result = scan_url(_model, req.url)
    return StreamingResponse(_scan_events(result), media_type="application/x-ndjson")


@app.post("/scan/result")
def scan_result(req: ScoreRequest):
    if _model is None:
        raise HTTPException(status_code=500, detail="Model not loaded.")
    return scan_url(_model, req.url)


@app.post("/api/analyze", response_class=StreamingResponse, responses=_NDJSON_RESPONSE)
def analyze(req: ScoreRequest):
    return StreamingResponse(_analyze_events(req.url), media_type="application/x-ndjson")


@app.post("/api/analyze/result")
def analyze_result(req: ScoreRequest):
    if _model is None:
        raise HTTPException(status_code=500, detail="Model not loaded.")

    normalized = _normalize_url_input(req.url)
    scan_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()
    raw_result = scan_url(_model, normalized)
    return _scrutinix_result(raw_result, scan_id, started_at)


@app.post("/scan/batch")
def scan_batch(payload: dict):
    if _model is None:
        raise HTTPException(status_code=500, detail="Model not loaded.")
    urls = payload.get("urls")
    if not isinstance(urls, list) or not urls:
        raise HTTPException(status_code=400, detail="Expected JSON body with non-empty 'urls' list.")
    if len(urls) > 100:
        raise HTTPException(status_code=400, detail="Batch size too large (max 100 URLs).")

    results = [scan_url(_model, str(u)) for u in urls]
    return {"product_name": settings.app_name, "count": len(results), "results": results}


@app.post("/api/analyze/batch", response_class=StreamingResponse, responses=_NDJSON_RESPONSE)
def analyze_batch(payload: dict):
    if _model is None:
        raise HTTPException(status_code=500, detail="Model not loaded.")
    urls = payload.get("urls")
    if not isinstance(urls, list) or not urls:
        raise HTTPException(status_code=400, detail="Expected JSON body with non-empty 'urls' list.")
    if len(urls) > 10:
        raise HTTPException(status_code=400, detail="Batch scans must contain between 1 and 10 URLs.")

    def events() -> Iterable[str]:
        yield json.dumps(
            {
                "type": "batch_started",
                "total": len(urls),
                "startedAt": datetime.now(timezone.utc).isoformat(),
            }
        ) + "\n"

        results = []
        for index, raw_url in enumerate(urls):
            normalized = _normalize_url_input(str(raw_url))
            yield json.dumps({"type": "url_started", "index": index, "url": normalized}) + "\n"

            scan_id = str(uuid.uuid4())
            started_at = datetime.now(timezone.utc).isoformat()
            raw_result = scan_url(_model, normalized)
            result = _scrutinix_result(raw_result, scan_id, started_at)
            results.append(result)

            yield json.dumps(
                {
                    "type": "url_complete",
                    "index": index,
                    "url": result["url"],
                    "result": result,
                }
            ) + "\n"

        yield json.dumps({"type": "batch_complete", "results": results}) + "\n"

    return StreamingResponse(events(), media_type="application/x-ndjson")


@app.post("/api/analyze/batch/result")
def analyze_batch_result(payload: dict):
    if _model is None:
        raise HTTPException(status_code=500, detail="Model not loaded.")
    urls = payload.get("urls")
    if not isinstance(urls, list) or not urls:
        raise HTTPException(status_code=400, detail="Expected JSON body with non-empty 'urls' list.")
    if len(urls) > 10:
        raise HTTPException(status_code=400, detail="Batch scans must contain between 1 and 10 URLs.")

    results = []
    for raw_url in urls:
        normalized = _normalize_url_input(str(raw_url))
        scan_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        raw_result = scan_url(_model, normalized)
        results.append(_scrutinix_result(raw_result, scan_id, started_at))
    return {"productName": settings.app_name, "count": len(results), "results": results}

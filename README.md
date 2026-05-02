# URL Trust Scorer

URL Trust Scorer is a local URL threat-scanning prototype. It combines URL lexical features, rule-based heuristics, a trained ML model, and novelty signals into a single trust score for browser, CLI, and API workflows.

The project is research-oriented and designed to run locally. It does not call commercial safe-browsing APIs by default.

## Features

- URL canonicalization and lexical feature extraction.
- Rule-based security heuristics with explainable reasons.
- ML-backed phishing probability from saved model artifacts.
- Multi-signal scan output with per-signal risk and score.
- Local dataset reputation from URLhaus exact malicious URLs and Tranco benign domains.
- Equal-weight evidence aggregation so the ML model is one layer, not the dominant decision maker.
- Novelty signals:
  - Homograph and brand-impersonation risk.
  - Temporal trust-drift risk.
- FastAPI endpoints for single scans, streaming scans, batch scans, and health checks.
- Scrutinix-compatible streaming aliases: `/api/analyze` and `/api/analyze/batch`.
- Swagger-friendly JSON result aliases: `/scan/result`, `/api/analyze/result`, and `/api/analyze/batch/result`.
- Chrome extension popup for active-tab scans, manual URL scans, signal details, and batch scans.

## Project Structure

```text
.
|-- app/
|   |-- main.py              # FastAPI entry point
|   |-- schemas.py           # Request / response schemas
|   `-- core/
|       |-- features.py      # URL feature extraction
|       |-- rules.py         # Heuristic penalty rules
|       |-- model.py         # Scoring logic and ML integration
|       |-- novelty.py       # Homograph and temporal drift signals
|       `-- scan_engine.py   # Multi-signal scan orchestration
|
|-- ml/
|   |-- download_datasets.py # URLhaus + Tranco downloader
|   |-- prepare_data.py      # Dataset preparation
|   |-- train.py             # Model training
|   |-- evaluate.py          # Model evaluation
|   |-- artifacts/           # Saved model and feature spec
|   `-- data/                # Local datasets
|
|-- scripts/
|   `-- score_url.py         # CLI scoring helper
|
|-- trust-score-extension/   # Chrome extension popup
`-- README.md
```

## Setup

Use Python 3.10 or newer. The current project was tested on Windows with Python 3.10.11, but the commands also work on macOS/Linux with the shell syntax adjusted where needed.

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

The repository includes the current reproducibility artifacts:

- `ml/data/urls.csv`
- `ml/artifacts/model.joblib`
- `ml/artifacts/feature_spec.json`
- `ml/artifacts/feature_importance.csv`

You can run immediately with those checked-in artifacts. To rebuild the dataset and model from public sources, run:

```bash
python -m ml.download_datasets --malicious-limit 50000 --benign-limit 50000
```

Then retrain with the same pruned feature set used by the checked-in model:

```powershell
$env:TRAIN_FEATURES='host_entropy,path_len,url_len,num_subdomains,num_special,tld_len,tld_in_top,path_entropy,registered_domain_len,uses_https,domain_len,host_len,subdomain_len,num_hyphens_host,num_digits,num_dots'
python -m ml.train
Remove-Item Env:\TRAIN_FEATURES
```

On macOS/Linux:

```bash
TRAIN_FEATURES='host_entropy,path_len,url_len,num_subdomains,num_special,tld_len,tld_in_top,path_entropy,registered_domain_len,uses_https,domain_len,host_len,subdomain_len,num_hyphens_host,num_digits,num_dots' python -m ml.train
```

Run the stricter reproducible evaluation:

```bash
python -m ml.check_accuracy
```

Expected challenge-set result:

```text
Rows used  : 62,005
Split      : domain
Test bal.  : True
Feature set: host-only
Accuracy  : about 0.898
F1        : about 0.887
ROC-AUC   : about 0.969
```

The intentionally inflated random-split baseline is still available for comparison:

```bash
python -m ml.check_accuracy --easy-random
```

Run automated tests:

```bash
python -m pytest
```

Start the local API:

```powershell
$env:FETCH_CONTENT="1"
$env:FETCH_INFRA="1"
$env:FETCH_EXTERNAL_JS="1"
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

The API defaults to `http://127.0.0.1:8000`.

Open Swagger UI:

```text
http://127.0.0.1:8000/docs
```

Use `/scan/result` or `/api/analyze/result` in Swagger when you want one parseable JSON object. The `/scan` and `/api/analyze` endpoints return newline-delimited streaming events (`application/x-ndjson`).

## API

### Health

```http
GET /health
```

Returns:

```json
{ "ok": true }
```

### Legacy Score

```http
POST /score
Content-Type: application/json

{ "url": "https://example.com" }
```

Returns the base scoring envelope.

### Streaming Scan

```http
POST /scan
Content-Type: application/json

{ "url": "https://example.com" }
```

Returns newline-delimited JSON (`application/x-ndjson`), not one JSON object. This is useful for live progress in a UI, but Swagger may show it as raw lines.

- `scan_started`
- `signal_result`
- `scan_complete`

For Swagger UI testing, use the single-object JSON endpoint instead:

```http
POST /scan/result
Content-Type: application/json

{ "url": "https://example.com" }
```

Example final result shape:

```json
{
  "product_name": "URL Trust Scorer",
  "url": "https://example.com",
  "trust_score": 92,
  "verdict": "SAFE",
  "risk": {
    "final": 0.08,
    "base": 0.08,
    "ml": 0.04,
    "heuristic": 0.0,
    "homograph_brand": 0.0,
    "temporal_drift": 0.0,
    "high_trust_allowlist": 0.0
  },
  "signals": [
    {
      "name": "lexical_ml",
      "risk": 0.04,
      "score": 96,
      "detail": "LightGBM phishing probability from extracted URL/content/infra features."
    }
  ],
  "reasons": []
}
```

### Batch Scan

```http
POST /scan/batch
Content-Type: application/json

{
  "urls": [
    "https://example.com",
    "https://login.example.test"
  ]
}
```

Batch requests accept up to 100 URLs.

### Scrutinix-Compatible Single Scan

```http
POST /api/analyze
Content-Type: application/json

{ "url": "https://example.com" }
```

Returns Scrutinix-style newline-delimited JSON events (`application/x-ndjson`) with a `type` field:

- `scan_started`
- `signal_result`
- `scan_complete`
- `scan_error` for unexpected failures

The final `scan_complete.result` contains Scrutinix-style `verdict`, `signals`, `threatInfo`, and `metadata` fields, plus `raw` with the native URL Trust Scorer scan envelope.

For Swagger UI testing, use:

```http
POST /api/analyze/result
Content-Type: application/json

{ "url": "https://example.com" }
```

### Scrutinix-Compatible Batch Scan

```http
POST /api/analyze/batch
Content-Type: application/json

{
  "urls": [
    "https://example.com",
    "https://github.com"
  ]
}
```

Returns streamed batch events:

- `batch_started`
- `url_started`
- `url_complete`
- `batch_complete`

This endpoint follows Scrutinix's smaller batch limit of 10 URLs.

For Swagger UI testing, use the JSON batch result endpoint:

```http
POST /api/analyze/batch/result
Content-Type: application/json

{
  "urls": [
    "https://example.com",
    "https://github.com"
  ]
}
```

## Chrome Extension

1. Start the API with `uvicorn app.main:app --reload`.
2. Open Chrome and go to `chrome://extensions/`.
3. Enable Developer mode.
4. Choose Load unpacked and select `trust-score-extension/`.
5. Open the popup from the toolbar.

The popup can scan the active tab, scan a manually entered URL, or run a newline-separated batch scan.

## Dataset Refresh

The downloader uses:

- URLhaus recent malicious URL feed: `https://urlhaus.abuse.ch/downloads/csv_recent/`
- Tranco top domains: `https://tranco-list.eu/top-1m.csv.zip`

It writes raw downloads to `ml/data/raw/` and the training CSV to `ml/data/urls.csv`.

```bash
python -m ml.download_datasets --malicious-limit 50000 --benign-limit 50000
python -m ml.train
python -m ml.feature_importance --top 30
python -m pytest
```

URLhaus labels are mapped into the existing binary malicious/phishing training class because the current model is binary.

At runtime, URL Trust Scorer also uses the downloaded dataset as reputation evidence:

- Exact URL match in the malicious dataset raises risk.
- Registered-domain match in the Tranco benign set can reduce false positives only when no heuristic danger fires.
- Heuristic danger still wins over benign-domain reputation for suspicious subdomains or paths.

## Scoring Model

The final verdict uses equal-weight evidence fusion over the available decision layers:

- Lexical ML risk.
- Heuristic rule risk.
- Dataset reputation when an exact malicious URL or known benign registered domain is available.
- High-trust allowlist when the registered domain is a major provider.

This replaces the earlier ML-heavy blend. The ML model is now treated as one evidence layer instead of the primary decision layer. If the ML model overfits on URL shape but reputation and rules are clean, those layers can counterbalance it.

Example:

```text
https://www.chess.com/home
ML layer: high risk
Heuristic layer: clean
Dataset reputation layer: clean benign domain
Final: SAFE, but lower-confidence score
```

The current trained model uses only the non-zero-importance feature set saved in `ml/artifacts/feature_spec.json`. To retrain with the same pruned set:

```powershell
$env:TRAIN_FEATURES='host_entropy,path_len,url_len,num_subdomains,num_special,tld_len,tld_in_top,path_entropy,registered_domain_len,uses_https,domain_len,host_len,subdomain_len,num_hyphens_host,num_digits,num_dots'
python -m ml.train
Remove-Item Env:\TRAIN_FEATURES
```

## CLI

Score a single URL from the terminal:

```bash
python scripts/score_url.py https://example.com
```

Or run the interactive terminal scanner:

```bash
python scripts/score_url.py
```

Paste a URL at the `URL>` prompt. Type `q` to quit. Add `--json` to print the full API response:

```bash
python scripts/score_url.py https://google.com --json
```

## Notes

- The prototype intentionally focuses on local URL and lightweight infrastructure signals.
- Scrutinix-style external providers such as VirusTotal and Google Safe Browsing are represented by local equivalents unless API-key integrations are added.
- The Chrome extension expects the local API at `http://127.0.0.1:8000`.

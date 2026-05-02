# URL Trust Scorer

URL Trust Scorer is a local phishing and malicious URL detection prototype. It takes a URL, analyzes it through multiple security signals, and returns a trust score, verdict, risk breakdown, and human-readable reasons.

The project is designed to run locally and reproducibly. It does not require paid threat-intelligence APIs.

## What It Does

- Extracts URL and domain-level features.
- Uses a trained LightGBM model to estimate phishing probability.
- Applies rule-based security heuristics for explainable warnings.
- Uses local reputation evidence from URLhaus and Tranco.
- Combines evidence layers with equal weighting instead of letting ML dominate.
- Adds novelty signals for homograph/brand impersonation and temporal trust drift.
- Provides a FastAPI backend, CLI scanner, batch scanning, and optional Chrome extension.

## Project Structure

```text
.
|-- app/
|   |-- main.py              # FastAPI app and API routes
|   |-- schemas.py           # Request/response schemas
|   `-- core/
|       |-- features.py      # URL and domain feature extraction
|       |-- rules.py         # Heuristic rules
|       |-- model.py         # Model loading and scoring logic
|       |-- reputation.py    # Local URLhaus/Tranco reputation checks
|       |-- novelty.py       # Homograph and temporal drift signals
|       `-- scan_engine.py   # Multi-signal scan orchestration
|
|-- ml/
|   |-- download_datasets.py # Downloads URLhaus + Tranco data
|   |-- train.py             # Trains the LightGBM model
|   |-- check_accuracy.py    # Reproducible evaluation script
|   |-- feature_importance.py
|   |-- artifacts/           # Saved model and feature metadata
|   `-- data/                # Training dataset
|
|-- scripts/
|   `-- score_url.py         # Terminal URL scanner
|
|-- tests/                   # Pytest tests
|-- trust-score-extension/   # Optional Chrome extension
`-- README.md
```

## Environment

Tested environment:

```text
OS: Windows
Python: 3.10.11
API framework: FastAPI
Model: LightGBM
```

Python 3.10 or newer is recommended.

## Setup

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

The repository already includes the main reproducibility artifacts:

```text
ml/data/urls.csv
ml/artifacts/model.joblib
ml/artifacts/feature_spec.json
ml/artifacts/feature_importance.csv
```

So you can run the project immediately after installing dependencies.

## Run the API

Start the local backend:

```powershell
$env:FETCH_CONTENT="1"
$env:FETCH_INFRA="1"
$env:FETCH_EXTERNAL_JS="1"
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open the API docs:

```text
http://127.0.0.1:8000/docs
```

Health check:

```text
http://127.0.0.1:8000/health
```

Expected response:

```json
{ "ok": true }
```

## Scan a URL

Use the CLI:

```powershell
python scripts\score_url.py https://www.chess.com/home --host http://127.0.0.1:8000
```

Interactive mode:

```powershell
python scripts\score_url.py --host http://127.0.0.1:8000
```

Paste a URL at the prompt. Type `q` to quit.

## Main API Endpoints

### Score One URL

```http
POST /score
Content-Type: application/json

{ "url": "https://example.com" }
```

Returns a JSON score result with verdict, trust score, risk values, reasons, and feature names.

### Scan One URL With Full Signals

For Swagger or simple JSON testing:

```http
POST /scan/result
Content-Type: application/json

{ "url": "https://example.com" }
```

For streaming scan progress:

```http
POST /scan
Content-Type: application/json

{ "url": "https://example.com" }
```

`/scan` returns newline-delimited JSON events:

```text
scan_started
signal_result
scan_complete
```

Use `/scan/result` if you want one normal JSON response.

### Batch Scan

```http
POST /scan/batch
Content-Type: application/json

{
  "urls": [
    "https://example.com",
    "https://github.com"
  ]
}
```

Batch scan accepts up to 100 URLs.

## Example Output

```text
=== URL Trust Scorer ===
URL          : https://chess.com/home
Verdict      : SAFE
Trust score  : 67/100
Prediction   : benign
Final risk   : 0.333
ML risk      : 1.000
Raw ML risk  : 1.000

Reasons:
- Registered domain appears in the local Tranco benign-domain dataset.
```

This example shows why the system uses multiple evidence layers. The ML model may be suspicious, but clean heuristic and reputation layers can reduce the final risk.

## Dataset

The checked-in dataset contains:

```text
Total rows : 76,195
Benign     : 50,000
Phishing   : 26,195
```

Data sources:

- URLhaus recent malicious URL feed
- Tranco top domains

To rebuild the dataset:

```powershell
python -m ml.download_datasets --malicious-limit 50000 --benign-limit 50000
```

The downloader writes:

```text
ml/data/urls.csv
```

## Train the Model

Retrain using the same pruned feature set used by the checked-in model:

```powershell
$env:TRAIN_FEATURES='host_entropy,path_len,url_len,num_subdomains,num_special,tld_len,tld_in_top,path_entropy,registered_domain_len,uses_https,domain_len,host_len,subdomain_len,num_hyphens_host,num_digits,num_dots'
python -m ml.train
Remove-Item Env:\TRAIN_FEATURES
```

The trained model is saved to:

```text
ml/artifacts/model.joblib
```

The selected feature list is saved to:

```text
ml/artifacts/feature_spec.json
```

## Evaluate the Model

Run the stricter reproducible evaluation:

```powershell
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

The stricter evaluation removes raw IP-host shortcut rows, uses domain-level splitting, uses host-only features, and reports on a balanced test set. This gives a more meaningful result than a simple random split.

To reproduce the easier random-split baseline:

```powershell
python -m ml.check_accuracy --easy-random
```

## Run Tests

```powershell
python -m pytest
```

Expected result:

```text
18 passed
```

## Scoring Logic

The final risk score is built from multiple evidence layers:

- ML lexical/domain risk
- heuristic rule risk
- dataset reputation risk
- high-trust allowlist evidence
- homograph/brand impersonation risk
- temporal trust drift risk

The final system uses equal-weight evidence fusion. This prevents the ML model from being the only decision maker.

Example:

```text
https://www.chess.com/home

ML layer: suspicious
Heuristic layer: clean
Dataset reputation layer: known benign domain
Final verdict: SAFE
```

## Optional Chrome Extension

1. Start the API on `http://127.0.0.1:8000`.
2. Open Chrome and go to `chrome://extensions/`.
3. Enable Developer mode.
4. Click Load unpacked.
5. Select the `trust-score-extension/` folder.

The extension can scan the active tab, scan a manually entered URL, and show signal details.

## Notes

- This is a local research prototype, not a production security gateway.
- The model is binary: benign vs phishing/malicious.
- The project does not require VirusTotal, Google Safe Browsing, or other paid/commercial APIs.
- Content and infrastructure fetching can be enabled through environment variables, but URL/domain scoring works with the included model artifacts.

# URL Trust Scorer

A research-oriented prototype for **URL trust scoring** using URL-level lexical features, rule-based heuristics, and machine learning. This system identifies potentially malicious links by analyzing patterns within the URL string itself, providing real-time scoring via a FastAPI backend and a Chrome extension.

This project is a **proof-of-concept** following a modality-based approach (starting with URL-only signals), with planned extensions to HTML-based and reputation-based features.

---

## 📐 System Architecture

The system follows a pipeline where a raw URL is processed through both statistical models and hardcoded security logic to produce a final "Trust Score."

1. **Input:** Request received via Chrome Extension or CLI.
2. **Canonicalization:** Standardizes the URL (e.g., removing fragments, handling `www`).
3. **Feature Extraction:** Generates numerical data (length, entropy, digit ratio, etc.).
4. **Dual-Path Analysis:**
   * **ML Path:** Random Forest classifier predicts risk based on trained patterns.
   * **Heuristic Path:** Hardcoded rules (e.g., IP addresses in URLs, excessive subdomains) provide explainable penalties.
5. **Aggregation:** Blends scores into a final Trust Score (0-100) and Verdict.

---

## ✨ Features

* **URL Lexical & Structural Extraction:** Analyzes entropy, special characters, and domain depth.
* **Rule-based Heuristics:** Provides transparency and "explainability" for risk flags.
* **Machine Learning:** Random Forest classifier trained on modern malicious datasets.
* **Weighted Blending:** Combines ML confidence with heuristic risk for a balanced score.
* **FastAPI Backend:** High-performance `/score` and `/health` endpoints.
* **Chrome Extension:** Real-time UI popup for scoring active browser tabs.

---

## 📁 Project Structure

```text
.
├── app/
│   ├── main.py              # FastAPI entry point
│   ├── schemas.py           # Request / response schemas
│   └── core/
│       ├── features.py      # URL feature extraction logic
│       ├── rules.py         # Heuristic penalty rules
│       └── model.py         # Scoring logic & ML integration
│
├── ml/
│   ├── prepare_data.py      # Dataset construction (URLHaus + Tranco)
│   ├── train.py             # Random Forest model training
│   ├── artifacts/           # Saved model files (.joblib / .pkl)
│   └── data/                # Raw CSV/Text datasets
│
├── scripts/
│   └── score_url.py         # CLI client for testing URLs
│
├── trust-score-extension/   # Chrome extension manifest and UI
│
└── README.md
```

---

## 🚀 How to Run

### 1. Installation

Clone the repository and install dependencies:

```bash
pip install -r requirements.txt
```

### 2. Prepare & Train

Generate the training features and train the Random Forest model:

```bash
# Prepare dataset
python -m ml.prepare_data

# Train the model
python -m ml.train
```

### 3. Start the Server

Launch the FastAPI backend using Uvicorn:

```bash
uvicorn app.main:app --reload
```

### 4. Test via CLI

Open a new terminal and score a specific URL:

```bash
python scripts/score_url.py https://example.com
```

---

## 🌐 API Reference

### Health Check

**GET /health**

Returns `{ "ok": true }` if the service and ML models are loaded.

### Score URL

**POST /score**

**Payload:** `{ "url": "string" }`

**Response Example:**

```json
{
  "url": "https://suspicious-site.net/login",
  "trust_score": 35,
  "verdict": "SUSPICIOUS",
  "risk": {
    "final": 0.65,
    "ml": 0.72,
    "heuristic": 0.40
  },
  "reasons": ["Contains IP address", "High number of subdomains"],
  "feature_names": ["url_len", "dot_count", "entropy", ...]
}
```

---

## 🧪 Datasets Used

The model is trained using a balance of malicious and benign data:

* **URLHaus:** Provides a feed of verified malicious URLs (malware distribution).
* **Tranco Top Sites:** Provides a ranking of popular, benign domains to reduce false positives.

---

## 🔍 Design Notes

* **URL-Only Context:** This prototype intentionally avoids fetching HTML or checking third-party APIs (like Google Safe Browsing) to demonstrate the power of lexical analysis.
* **Scoring Ceiling:** Well-known domains may peak at a ~70–80 trust score. Achieving a 90+ score typically requires "Reputation" signals (e.g., Whois age) not included in this URL-only version.
* **Explainability:** Every heuristic hit is returned in the reasons array, helping the user understand why a score is low.

---

## 🧩 Chrome Extension

The included extension allows for one-click scoring of the current tab.

1. Open Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode**.
3. Click **Load unpacked** and select the `trust-score-extension/` folder.
4. Ensure the FastAPI server is running locally to see results.

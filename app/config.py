from __future__ import annotations
from pydantic import BaseModel
from dotenv import load_dotenv
import os
from pathlib import Path

load_dotenv()

BASE_DIR = Path(__file__).resolve().parents[1]
ML_DIR = BASE_DIR / "ml"
ARTIFACT_DIR = ML_DIR / "artifacts"

# Registered domains (e.g. google.com for any *.google.com). Extended via HIGH_TRUST_DOMAINS_EXTRA.
_DEFAULT_HIGH_TRUST_DOMAINS: frozenset[str] = frozenset(
    {
        "google.com",
        "gstatic.com",
        "googleapis.com",
        "googleusercontent.com",
        "youtube.com",
        "youtu.be",
        "microsoft.com",
        "live.com",
        "office.com",
        "apple.com",
        "icloud.com",
        "amazon.com",
        "amazonaws.com",
        "cloudflare.com",
        "github.com",
        "mozilla.org",
        "wikipedia.org",
        "reddit.com",
        "linkedin.com",
        "twitter.com",
        "x.com",
        "facebook.com",
        "instagram.com",
        "netflix.com",
        "adobe.com",
        "dropbox.com",
        "paypal.com",
        "ebay.com",
    }
)


def high_trust_domain_set() -> frozenset[str]:
    extra = os.getenv("HIGH_TRUST_DOMAINS_EXTRA", "")
    if not extra.strip():
        return _DEFAULT_HIGH_TRUST_DOMAINS
    more = {p.strip().lower() for p in extra.split(",") if p.strip()}
    return _DEFAULT_HIGH_TRUST_DOMAINS | more


class Settings(BaseModel):
    app_name: str = os.getenv("APP_NAME", "URL Trust Scorer")
    model_path: str = os.getenv("MODEL_PATH", str(ARTIFACT_DIR / "model.joblib"))
    fetch_content: bool = os.getenv("FETCH_CONTENT", "1") == "1"
    fetch_infra: bool = os.getenv("FETCH_INFRA", "1") == "1"
    fetch_external_js: bool = os.getenv("FETCH_EXTERNAL_JS", "1") == "1"
    max_html_bytes: int = int(os.getenv("MAX_HTML_BYTES", "1000000"))
    max_js_bytes: int = int(os.getenv("MAX_JS_BYTES", "200000"))
    max_js_files: int = int(os.getenv("MAX_JS_FILES", "5"))
    request_timeout: float = float(os.getenv("REQUEST_TIMEOUT", "5.0"))
    high_trust_allowlist: bool = os.getenv("HIGH_TRUST_ALLOWLIST", "1") == "1"
    high_trust_score: int = int(os.getenv("HIGH_TRUST_SCORE", "95"))


settings = Settings()

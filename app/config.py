from __future__ import annotations
from pydantic import BaseModel
from dotenv import load_dotenv
import os
from pathlib import Path

load_dotenv()

BASE_DIR = Path(__file__).resolve().parents[1]
ML_DIR = BASE_DIR / "ml"
ARTIFACT_DIR = ML_DIR / "artifacts"


class Settings(BaseModel):
    app_name: str = os.getenv("APP_NAME", "URL Trust Scorer")
    model_path: str = os.getenv("MODEL_PATH", str(ARTIFACT_DIR / "model.joblib"))


settings = Settings()

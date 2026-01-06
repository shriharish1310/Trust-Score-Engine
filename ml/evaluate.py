from __future__ import annotations
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix

from app.core.features import vectorize

ARTIFACT_DIR = Path(__file__).resolve().parent / "artifacts"
MODEL_PATH = ARTIFACT_DIR / "model.joblib"


def load_data() -> pd.DataFrame:
    data_path = Path(__file__).resolve().parent / "data" / "urls.csv"
    if not data_path.exists():
        raise FileNotFoundError(
            f"Missing dataset at {data_path}\n"
            "Create ml/data/urls.csv with columns: url,label"
        )
    df = pd.read_csv(data_path)
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("CSV must contain columns: url,label")
    df = df.dropna(subset=["url", "label"])
    df["label"] = df["label"].astype(int)
    return df


def main() -> None:
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Model not found at {MODEL_PATH}. Train first: python -m ml.train")

    df = load_data()
    X = np.array([vectorize(u) for u in df["url"].astype(str)], dtype=float)
    y = df["label"].to_numpy(dtype=int)

    model = joblib.load(MODEL_PATH)
    proba = model.predict_proba(X)[:, 1]
    pred = (proba >= 0.5).astype(int)

    print("ROC-AUC:", roc_auc_score(y, proba))
    print("Confusion Matrix:\n", confusion_matrix(y, pred))
    print(classification_report(y, pred))


if __name__ == "__main__":
    main()

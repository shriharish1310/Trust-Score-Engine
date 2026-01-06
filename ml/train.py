from __future__ import annotations

from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    average_precision_score,
)
from sklearn.model_selection import train_test_split

from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV

from app.core.features import vectorize, SPEC


ML_DIR = Path(__file__).resolve().parent
DATA_PATH = ML_DIR / "data" / "urls.csv"
ARTIFACT_DIR = ML_DIR / "artifacts"
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

MODEL_PATH = ARTIFACT_DIR / "model.joblib"
SPEC_PATH = ARTIFACT_DIR / "feature_spec.json"


def load_data() -> pd.DataFrame:
    """
    Expected CSV format:
      url,label
      https://example.com,0
      http://bad-login-verify.com/login,1

    label: 0=benign, 1=malicious
    """
    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"Missing dataset at: {DATA_PATH}\n"
            "Create ml/data/urls.csv with columns: url,label"
        )

    df = pd.read_csv(DATA_PATH)

    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("CSV must contain columns: url,label")

    df = df.dropna(subset=["url", "label"]).copy()
    df["url"] = df["url"].astype(str)
    df["label"] = df["label"].astype(int)

    # Basic sanity: labels must be 0/1
    bad_labels = df.loc[~df["label"].isin([0, 1])]
    if len(bad_labels) > 0:
        raise ValueError("Found labels outside {0,1}. Fix your dataset labels.")

    return df


def build_xy(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    X = np.array([vectorize(u) for u in df["url"]], dtype=float)
    y = df["label"].to_numpy(dtype=int)
    return X, y


def main() -> None:
    df = load_data()
    X, y = build_xy(df)

    # Train/test split
    stratify_arg = y if (len(y) >= 10 and len(set(y)) > 1) else None

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2 if len(y) >= 10 else 0.5,
        random_state=42,
        stratify=stratify_arg,
    )

    # Calibrated Logistic Regression (better probabilities for trust scoring)
    base = Pipeline(
        [
            ("scaler", StandardScaler()),
            ("lr", LogisticRegression(max_iter=800, class_weight="balanced")),
        ]
    )

    # Calibration gives more reliable probabilities than raw LR/RF
    # If you ever hit "not enough samples for cv", change cv=3 -> cv=2
    model = CalibratedClassifierCV(base, method="isotonic", cv=3)
    model.fit(X_train, y_train)

    # Evaluate
    proba = model.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)

    # Metrics
    try:
        roc = roc_auc_score(y_test, proba)
    except ValueError:
        roc = float("nan")

    try:
        ap = average_precision_score(y_test, proba)
    except ValueError:
        ap = float("nan")

    print("=== Evaluation (test split) ===")
    print("ROC-AUC:", roc)
    print("Avg Precision (PR-AUC):", ap)
    print("Confusion Matrix:\n", confusion_matrix(y_test, pred))
    print(classification_report(y_test, pred, digits=4))

    # Save artifacts
    joblib.dump(model, MODEL_PATH)

    with open(SPEC_PATH, "w", encoding="utf-8") as f:
        json.dump({"feature_names": list(SPEC.names)}, f, indent=2)

    print("\nSaved model ->", MODEL_PATH)
    print("Saved feature spec ->", SPEC_PATH)


if __name__ == "__main__":
    main()

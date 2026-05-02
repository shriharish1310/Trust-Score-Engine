from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import pandas as pd


ML_DIR = Path(__file__).resolve().parent
ARTIFACT_DIR = ML_DIR / "artifacts"
MODEL_PATH = ARTIFACT_DIR / "model.joblib"
SPEC_PATH = ARTIFACT_DIR / "feature_spec.json"
OUT_PATH = ARTIFACT_DIR / "feature_importance.csv"


def load_feature_names() -> list[str]:
    if SPEC_PATH.exists():
        data = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
        names = data.get("feature_names")
        if isinstance(names, list):
            return [str(name) for name in names]
    raise FileNotFoundError(f"Missing feature spec at {SPEC_PATH}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Report model feature importances.")
    parser.add_argument("--out", default=str(OUT_PATH), help="CSV output path.")
    parser.add_argument("--top", type=int, default=25, help="Number of top features to print.")
    args = parser.parse_args()

    model = joblib.load(MODEL_PATH)
    names = load_feature_names()
    importances = getattr(model, "feature_importances_", None)
    if importances is None:
        raise ValueError("The trained model does not expose feature_importances_.")

    rows = pd.DataFrame(
        {
            "feature": names[: len(importances)],
            "importance": [float(value) for value in importances],
        }
    )
    rows["rank"] = rows["importance"].rank(method="first", ascending=False).astype(int)
    rows = rows.sort_values(["importance", "feature"], ascending=[False, True]).reset_index(drop=True)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    rows.to_csv(out_path, index=False)

    non_zero = rows[rows["importance"] > 0]
    zero = rows[rows["importance"] <= 0]

    print(f"Saved: {out_path}")
    print(f"Features: {len(rows)} total, {len(non_zero)} non-zero, {len(zero)} zero")
    print("\nTop features:")
    for item in non_zero.head(args.top).itertuples(index=False):
        print(f"{int(item.rank):>2}. {item.feature}: {item.importance:g}")

    if not zero.empty:
        print("\nZero-importance features:")
        print(", ".join(zero["feature"].tolist()))


if __name__ == "__main__":
    main()

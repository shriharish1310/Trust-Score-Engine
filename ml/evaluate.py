from __future__ import annotations

from functools import lru_cache
from pathlib import Path
import os
import re
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, f1_score, roc_auc_score

from app.core.features import vectorize
from app.core.infrastructure import INFRA_SPEC, fetch_infrastructure


ARTIFACT_DIR = Path(__file__).resolve().parent / "artifacts"
MODEL_PATH = ARTIFACT_DIR / "model.joblib"
DATA_PATH = Path(__file__).resolve().parent / "data" / "urls.csv"

BINARY_LABELS = ("benign", "phishing")


def load_data() -> pd.DataFrame:
    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"Missing dataset at {DATA_PATH}\n"
            "Create ml/data/urls.csv with columns: url,label,label_name"
        )
    df = pd.read_csv(DATA_PATH)
    if "url" not in df.columns:
        raise ValueError("CSV must contain column: url")

    df["url"] = df["url"].astype(str)

    if "label_name" not in df.columns:
        if "label" not in df.columns:
            raise ValueError("CSV must contain label_name or numeric label column.")
        if df["label"].dtype == object:
            df["label_name"] = df["label"].astype(str)
        else:
            df["label"] = df["label"].astype(int)
            label_vals = set(df["label"].unique())
            if label_vals.issubset({0, 1}):
                df["label_name"] = df["label"].map({0: "benign", 1: "phishing"})
            else:
                df["label_name"] = df["label"].map({0: "benign", 2: "phishing"})

    df["label_name"] = df["label_name"].astype(str).str.strip().str.lower()
    df = df[df["label_name"].isin(BINARY_LABELS)].copy()
    if df.empty:
        raise ValueError("No rows labeled as benign/phishing after filtering.")

    df["label"] = (df["label_name"] == "phishing").astype(int)
    return df


def _resolve_path(base_dir: Path, raw: str) -> Path:
    p = Path(str(raw))
    if p.is_absolute():
        return p
    return (base_dir / p).resolve()


@lru_cache(maxsize=256)
def _read_text_file(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="ignore")


def _split_paths(value: str | None) -> list[str]:
    if value is None or (isinstance(value, float) and np.isnan(value)):
        return []
    if not isinstance(value, str):
        return []
    parts = re.split(r"[;,]", value)
    return [p.strip() for p in parts if p.strip()]


def _infra_row_meta(row: object, cols: set[str], _get, url: str) -> dict[str, float] | None:
    present = [n for n in INFRA_SPEC.names if n in cols]
    if present:
        out = {name: 0.0 for name in INFRA_SPEC.names}
        for name in present:
            v = _get(row, name)
            if v is not None and not pd.isna(v):
                out[name] = float(v)
        return out
    if os.getenv("TRAIN_FETCH_INFRA", "0") != "1":
        return None
    pu = urlparse(url if "://" in url else "http://" + url)
    h = (pu.hostname or "").strip()
    if not h:
        return None
    to = float(os.getenv("TRAIN_INFRA_TIMEOUT", "5"))
    return fetch_infrastructure(h, timeout=to)


def _build_degree_maps(df: pd.DataFrame) -> dict[str, pd.Series]:
    maps: dict[str, pd.Series] = {}
    for col in ("ip", "asn", "ssl_issuer", "brand"):
        if col in df.columns:
            series = df[col].astype(str).fillna("")
            maps[col] = series.value_counts()
    return maps


def build_xy(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    base_dir = DATA_PATH.parent
    cols = set(df.columns)
    degree_maps = _build_degree_maps(df)

    def _get(row, name: str):
        return getattr(row, name) if name in cols else None

    rows: list[list[float]] = []
    for row in df.itertuples(index=False):
        url = str(getattr(row, "url"))

        html = None
        if "html" in cols:
            html_val = _get(row, "html")
            if isinstance(html_val, str) and html_val.strip():
                html = html_val
        if html is None and "html_path" in cols:
            html_path_val = _get(row, "html_path")
            for p in _split_paths(html_path_val):
                path = _resolve_path(base_dir, p)
                if path.exists():
                    html = _read_text_file(str(path))
                    break

        js_texts: list[str] = []
        if "js" in cols:
            js_val = _get(row, "js")
            if isinstance(js_val, str) and js_val.strip():
                js_texts.append(js_val)
        if "js_path" in cols:
            js_path_val = _get(row, "js_path")
            for p in _split_paths(js_path_val):
                path = _resolve_path(base_dir, p)
                if path.exists():
                    js_texts.append(_read_text_file(str(path)))

        meta: dict[str, float | str] = {}
        if "brand" in cols:
            brand_val = _get(row, "brand")
            if brand_val is not None and not pd.isna(brand_val):
                meta["brand"] = str(brand_val)
                if "brand" in degree_maps:
                    meta["brand_degree"] = float(degree_maps["brand"].get(str(brand_val), 0))

        if "ip" in degree_maps:
            ip_val = _get(row, "ip")
            if ip_val is not None and not pd.isna(ip_val):
                meta["ip_degree"] = float(degree_maps["ip"].get(str(ip_val), 0))
        if "asn" in degree_maps:
            asn_val = _get(row, "asn")
            if asn_val is not None and not pd.isna(asn_val):
                meta["asn_degree"] = float(degree_maps["asn"].get(str(asn_val), 0))
        if "ssl_issuer" in degree_maps:
            ssl_val = _get(row, "ssl_issuer")
            if ssl_val is not None and not pd.isna(ssl_val):
                meta["ssl_issuer_degree"] = float(degree_maps["ssl_issuer"].get(str(ssl_val), 0))

        infra = _infra_row_meta(row, cols, _get, url)
        if infra is not None:
            meta["infra"] = infra

        rows.append(vectorize(url, html=html, js_texts=js_texts, metadata=meta))

    X = np.array(rows, dtype=float)
    y = df["label"].to_numpy(dtype=int)
    return X, y


def main() -> None:
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Model not found at {MODEL_PATH}. Train first: python -m ml.train")

    df = load_data()
    X, y = build_xy(df)

    model = joblib.load(MODEL_PATH)
    proba = model.predict_proba(X)[:, 1]
    pred = (proba >= 0.5).astype(int)

    print("F1:", f1_score(y, pred))
    print("Confusion Matrix:\n", confusion_matrix(y, pred))
    print(classification_report(y, pred, digits=4, target_names=list(BINARY_LABELS)))

    try:
        print("ROC-AUC:", roc_auc_score(y, proba))
    except ValueError:
        print("ROC-AUC: nan")


if __name__ == "__main__":
    main()

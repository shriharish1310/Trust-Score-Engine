from __future__ import annotations

import argparse
import re
import json
from pathlib import Path
from urllib.parse import urlparse

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
import tldextract
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit, train_test_split

from ml.train import BINARY_LABELS, DATA_PATH, MODEL_PATH, SPEC_PATH, build_xy, load_data


ROBUST_FEATURES = [
    "host_entropy",
    "path_len",
    "url_len",
    "num_subdomains",
    "num_special",
    "tld_len",
    "path_entropy",
    "registered_domain_len",
    "uses_https",
    "domain_len",
    "host_len",
    "subdomain_len",
    "num_hyphens_host",
    "num_digits",
    "num_dots",
]


STRICT_FEATURES = [
    "host_entropy",
    "path_len",
    "url_len",
    "num_subdomains",
    "num_special",
    "path_entropy",
    "registered_domain_len",
    "domain_len",
    "host_len",
    "subdomain_len",
    "num_hyphens_host",
    "num_digits",
    "num_dots",
]


HOST_ONLY_FEATURES = [
    "host_entropy",
    "num_subdomains",
    "tld_len",
    "registered_domain_len",
    "uses_https",
    "domain_len",
    "host_len",
    "subdomain_len",
    "num_hyphens_host",
    "num_digits",
    "num_dots",
]


def load_saved_feature_names() -> list[str] | None:
    if not SPEC_PATH.exists():
        return None
    with open(SPEC_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    names = data.get("feature_names")
    if isinstance(names, list):
        return [str(name) for name in names]
    return None


def _host(url: str) -> str:
    value = str(url)
    if "://" not in value:
        value = "http://" + value
    return (urlparse(value).hostname or "").lower()


def _registered_domain(url: str) -> str:
    host = _host(url)
    ext = tldextract.extract(host)
    registered = ".".join(part for part in (ext.domain, ext.suffix) if part)
    return registered or host


def _is_ip_host(url: str) -> bool:
    return re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", _host(url)) is not None


def choose_feature_names(mode: str) -> list[str] | None:
    if mode == "saved":
        return load_saved_feature_names()
    if mode == "robust":
        return ROBUST_FEATURES
    if mode == "strict":
        return STRICT_FEATURES
    if mode == "host-only":
        return HOST_ONLY_FEATURES
    return None


def balance_classes(df: pd.DataFrame) -> pd.DataFrame:
    counts = df["label"].value_counts()
    if len(counts) < 2:
        return df
    n = int(counts.min())
    return (
        df.groupby("label", group_keys=False)[list(df.columns)]
        .apply(lambda part: part.sample(n=n, random_state=42))
        .sample(frac=1.0, random_state=42)
        .reset_index(drop=True)
    )


def balance_test_set(
    X_test: np.ndarray,
    y_test: np.ndarray,
    proba: np.ndarray,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    labels, counts = np.unique(y_test, return_counts=True)
    if len(labels) < 2:
        return X_test, y_test, proba
    n = int(counts.min())
    selected: list[np.ndarray] = []
    rng = np.random.default_rng(42)
    for label in labels:
        idx = np.flatnonzero(y_test == label)
        selected.append(rng.choice(idx, size=n, replace=False))
    keep = np.concatenate(selected)
    rng.shuffle(keep)
    return X_test[keep], y_test[keep], proba[keep]


def split_data(
    X: np.ndarray,
    y: np.ndarray,
    df: pd.DataFrame,
    split: str,
    test_size: float,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    if split == "random":
        return train_test_split(
            X,
            y,
            test_size=test_size,
            random_state=42,
            stratify=y,
        )

    groups = df["registered_domain"].to_numpy()
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=42)
    train_idx, test_idx = next(splitter.split(X, y, groups=groups))
    return X[train_idx], X[test_idx], y[train_idx], y[test_idx]


def make_model() -> lgb.LGBMClassifier:
    return lgb.LGBMClassifier(
        objective="binary",
        n_estimators=800,
        learning_rate=0.05,
        num_leaves=63,
        max_depth=-1,
        min_child_samples=20,
        subsample=0.85,
        colsample_bytree=0.85,
        reg_lambda=1.0,
        random_state=42,
        n_jobs=-1,
        verbosity=-1,
    )


def print_metrics(y_true: np.ndarray, proba: np.ndarray, threshold: float) -> None:
    pred = (proba >= threshold).astype(int)

    print("\n=== Metrics ===")
    print(f"Threshold : {threshold:.2f}")
    print(f"Accuracy  : {accuracy_score(y_true, pred):.4f}")
    print(f"Balanced Acc.: {balanced_accuracy_score(y_true, pred):.4f}")
    print(f"Precision : {precision_score(y_true, pred, zero_division=0):.4f}")
    print(f"Recall    : {recall_score(y_true, pred, zero_division=0):.4f}")
    print(f"F1        : {f1_score(y_true, pred, zero_division=0):.4f}")
    try:
        print(f"ROC-AUC   : {roc_auc_score(y_true, proba):.4f}")
    except ValueError:
        print("ROC-AUC   : nan")

    print("\nConfusion matrix:")
    print("Rows = actual, columns = predicted")
    print(confusion_matrix(y_true, pred))

    report = classification_report(
        y_true,
        pred,
        target_names=list(BINARY_LABELS),
        digits=4,
        zero_division=0,
        output_dict=True,
    )
    print("\nPer-class report:")
    for label in BINARY_LABELS:
        row = report[label]
        print(
            f"{label:>8}  "
            f"precision={row['precision']:.4f}  "
            f"recall={row['recall']:.4f}  "
            f"f1={row['f1-score']:.4f}  "
            f"support={int(row['support'])}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check URL Trust Scorer model accuracy on a held-out test split."
    )
    parser.add_argument("--test-size", type=float, default=0.2, help="Fraction of rows used for testing.")
    parser.add_argument("--threshold", type=float, default=0.5, help="Phishing probability cutoff.")
    parser.add_argument("--limit", type=int, default=0, help="Optional row limit for quick checks.")
    parser.add_argument(
        "--split",
        choices=["random", "domain"],
        default="domain",
        help="random is easier; domain keeps registered domains from appearing in both train and test.",
    )
    parser.add_argument(
        "--features",
        choices=["saved", "robust", "strict", "host-only", "all"],
        default="host-only",
        help="saved uses feature_spec.json; robust/strict remove some source-biased shortcuts.",
    )
    parser.add_argument(
        "--keep-ip-hosts",
        dest="drop_ip_hosts",
        action="store_false",
        default=True,
        help="Keep raw IPv4-host URLs. By default these are removed because only malicious rows contain them.",
    )
    parser.add_argument(
        "--balance",
        action="store_true",
        help="Downsample the larger class before splitting.",
    )
    parser.add_argument(
        "--unbalanced-test",
        dest="balanced_test",
        action="store_false",
        default=True,
        help="Report metrics on the natural imbalanced test distribution instead of an equal benign/phishing test sample.",
    )
    parser.add_argument(
        "--easy-random",
        action="store_true",
        help="Reproduce the inflated random-split style metric using saved features and IP-host shortcuts.",
    )
    parser.add_argument(
        "--saved-model",
        action="store_true",
        help="Evaluate ml/artifacts/model.joblib on the split instead of training a temporary model.",
    )
    args = parser.parse_args()

    if args.easy_random:
        args.split = "random"
        args.features = "saved"
        args.drop_ip_hosts = False
        args.balanced_test = False

    df = load_data()
    df["host"] = df["url"].map(_host)
    df["registered_domain"] = df["url"].map(_registered_domain)
    df["is_ip_host"] = df["url"].map(_is_ip_host)

    original_rows = len(df)
    if args.drop_ip_hosts:
        df = df[~df["is_ip_host"]].copy()
    if args.balance:
        df = balance_classes(df)
    if args.limit > 0:
        df = df.sample(n=min(args.limit, len(df)), random_state=42).reset_index(drop=True)

    feature_names = choose_feature_names(args.features)
    X, y = build_xy(df, feature_names=feature_names)

    X_train, X_test, y_train, y_test = split_data(X, y, df, args.split, args.test_size)

    print("=== Dataset ===")
    print(f"CSV        : {DATA_PATH}")
    print(f"Original   : {original_rows:,}")
    print(f"Rows used  : {len(df):,}")
    print(f"Train rows : {len(y_train):,}")
    print(f"Test rows  : {len(y_test):,}")
    print(f"Benign     : {(y == 0).sum():,}")
    print(f"Phishing   : {(y == 1).sum():,}")
    print(f"IP hosts   : {int(df['is_ip_host'].sum()):,}")
    print(f"Split      : {args.split}")
    print(f"Balanced   : {args.balance}")
    print(f"Test bal.  : {args.balanced_test}")
    print(f"Feature set: {args.features}")
    print(f"Features   : {len(feature_names) if feature_names else X.shape[1]}")

    if args.saved_model:
        if not Path(MODEL_PATH).exists():
            raise FileNotFoundError(f"Saved model not found: {MODEL_PATH}")
        print("\nMode       : saved model evaluation")
        print("Note       : if this model was trained on the same CSV, this may overestimate accuracy.")
        model = joblib.load(MODEL_PATH)
    else:
        print("\nMode       : fresh train/test evaluation")
        counts = np.bincount(y_train, minlength=2).astype(float)
        class_w = counts.sum() / (2.0 * np.maximum(counts, 1.0))
        sample_w = class_w[y_train]

        model = make_model()
        model.fit(
            X_train,
            y_train,
            sample_weight=sample_w,
            eval_set=[(X_test, y_test)],
            eval_metric="binary_logloss",
            callbacks=[lgb.early_stopping(stopping_rounds=60, verbose=False)],
        )

    proba = model.predict_proba(X_test)[:, 1]
    if args.balanced_test:
        X_test, y_test, proba = balance_test_set(X_test, y_test, proba)
        print(f"\nBalanced test rows: {len(y_test):,}")
    print_metrics(y_test, proba, args.threshold)


if __name__ == "__main__":
    main()

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import io
from pathlib import Path
import re
from typing import Any

import joblib
import numpy as np
import pandas as pd

try:
    from sklearn.compose import ColumnTransformer
    from sklearn.impute import SimpleImputer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import OneHotEncoder, StandardScaler
except ImportError as exc:  # pragma: no cover - dependency validation path
    raise RuntimeError("RiskBridge ML requires scikit-learn. Install with pip install -e '.[ml]' or pip install scikit-learn joblib") from exc

NUMERIC_FEATURES = [
    "cvss_score",
    "epss",
    "epss_percentile",
    "epss_delta_7d",
    "epss_delta_30d",
    "days_since_published",
]
CATEGORICAL_FEATURES = [
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "scope_metric",
    "cwe_primary",
]
TARGET = "exploited_within_30d"
DATE_COLUMN = "observation_date"


def _metric(vector: str, key: str) -> str:
    if not vector:
        return "UNKNOWN"
    match = re.search(rf"(?:^|/){re.escape(key)}:([^/]+)", str(vector))
    return match.group(1) if match else "UNKNOWN"


def prepare_ml_features(df: pd.DataFrame, *, observation_date: str | None = None) -> pd.DataFrame:
    out = df.copy()
    vector = out.get("cvss_vector", pd.Series([""] * len(out), index=out.index)).fillna("").astype(str)
    out["attack_vector"] = vector.apply(lambda v: _metric(v, "AV"))
    out["attack_complexity"] = vector.apply(lambda v: _metric(v, "AC"))
    out["privileges_required"] = vector.apply(lambda v: _metric(v, "PR"))
    out["user_interaction"] = vector.apply(lambda v: _metric(v, "UI"))
    out["scope_metric"] = vector.apply(lambda v: _metric(v, "S"))
    out["cwe_primary"] = out.get("cwe", pd.Series([""] * len(out), index=out.index)).fillna("").astype(str).apply(
        lambda x: (re.search(r"CWE-\d+", x).group(0) if re.search(r"CWE-\d+", x) else "UNKNOWN")
    )

    published = pd.to_datetime(out.get("published"), errors="coerce", utc=True)
    if observation_date:
        obs = pd.Timestamp(observation_date, tz="UTC")
        out["days_since_published"] = (obs - published).dt.days.clip(lower=0)
    elif DATE_COLUMN in out.columns:
        obs = pd.to_datetime(out[DATE_COLUMN], errors="coerce", utc=True)
        out["days_since_published"] = (obs - published).dt.days.clip(lower=0)
    else:
        now = pd.Timestamp(datetime.now(timezone.utc))
        out["days_since_published"] = (now - published).dt.days.clip(lower=0)

    for col in NUMERIC_FEATURES:
        if col not in out.columns:
            out[col] = np.nan
        out[col] = pd.to_numeric(out[col], errors="coerce")
    for col in CATEGORICAL_FEATURES:
        if col not in out.columns:
            out[col] = "UNKNOWN"
        out[col] = out[col].fillna("UNKNOWN").astype(str)
    return out


def _pipeline() -> Pipeline:
    numeric = Pipeline([
        ("impute", SimpleImputer(strategy="median")),
        ("scale", StandardScaler()),
    ])
    categorical = Pipeline([
        ("impute", SimpleImputer(strategy="most_frequent")),
        ("onehot", OneHotEncoder(handle_unknown="ignore")),
    ])
    prep = ColumnTransformer([
        ("num", numeric, NUMERIC_FEATURES),
        ("cat", categorical, CATEGORICAL_FEATURES),
    ])
    model = LogisticRegression(
        max_iter=3000,
        class_weight="balanced",
        solver="liblinear",
        random_state=42,
    )
    return Pipeline([("preprocessor", prep), ("model", model)])


def _precision_at_k(y_true: np.ndarray, probabilities: np.ndarray, k: int) -> float:
    if len(y_true) == 0:
        return 0.0
    k = max(1, min(int(k), len(y_true)))
    idx = np.argsort(probabilities)[::-1][:k]
    return float(np.mean(y_true[idx]))


def train_exploitation_model(df: pd.DataFrame) -> tuple[dict[str, Any], dict[str, Any]]:
    """Train a transparent baseline exploitation model using a chronological holdout.

    Required columns:
      observation_date, exploited_within_30d, cvss_score, epss, epss_percentile,
      published, cvss_vector, cwe. EPSS velocity columns are optional.

    Training data must be point-in-time observations. Do not populate features using information
    that became known after observation_date.
    """
    if DATE_COLUMN not in df.columns or TARGET not in df.columns:
        raise ValueError(f"Training CSV must contain '{DATE_COLUMN}' and '{TARGET}'.")

    work = df.copy()
    work[DATE_COLUMN] = pd.to_datetime(work[DATE_COLUMN], errors="coerce", utc=True)
    work[TARGET] = pd.to_numeric(work[TARGET], errors="coerce")
    work = work.dropna(subset=[DATE_COLUMN, TARGET]).sort_values(DATE_COLUMN).reset_index(drop=True)
    work = work[work[TARGET].isin([0, 1])]
    if len(work) < 30:
        raise ValueError("At least 30 labeled point-in-time observations are required for the baseline ML model.")
    if work[TARGET].nunique() < 2:
        raise ValueError("Training data must contain both exploited (1) and not-exploited (0) labels.")

    features = prepare_ml_features(work)
    split = max(1, int(len(work) * 0.80))
    if split >= len(work):
        split = len(work) - 1
    train = features.iloc[:split]
    test = features.iloc[split:]
    y_train = work.iloc[:split][TARGET].astype(int).to_numpy()
    y_test = work.iloc[split:][TARGET].astype(int).to_numpy()
    if len(np.unique(y_train)) < 2:
        raise ValueError("Chronological training partition contains only one class; provide a larger/more representative time range.")

    pipe = _pipeline()
    pipe.fit(train[NUMERIC_FEATURES + CATEGORICAL_FEATURES], y_train)
    prob = pipe.predict_proba(test[NUMERIC_FEATURES + CATEGORICAL_FEATURES])[:, 1]

    metrics: dict[str, Any] = {
        "rows": int(len(work)),
        "train_rows": int(len(train)),
        "test_rows": int(len(test)),
        "train_start": str(work.iloc[0][DATE_COLUMN]),
        "train_end": str(work.iloc[split - 1][DATE_COLUMN]),
        "test_start": str(work.iloc[split][DATE_COLUMN]),
        "test_end": str(work.iloc[-1][DATE_COLUMN]),
        "positive_rate_test": round(float(np.mean(y_test)), 6) if len(y_test) else None,
        "pr_auc": round(float(average_precision_score(y_test, prob)), 6) if len(np.unique(y_test)) > 1 else None,
        "roc_auc": round(float(roc_auc_score(y_test, prob)), 6) if len(np.unique(y_test)) > 1 else None,
        "brier_score": round(float(brier_score_loss(y_test, prob)), 6) if len(y_test) else None,
        "precision_at_10": round(_precision_at_k(y_test, prob, min(10, len(y_test))), 6),
    }
    metadata = {
        "model_name": "RiskBridge Emerging Exploitation Model (REEM)",
        "model_type": "LogisticRegression",
        "target": TARGET,
        "horizon_days": 30,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "numeric_features": NUMERIC_FEATURES,
        "categorical_features": CATEGORICAL_FEATURES,
        "important_warning": "Use point-in-time features only. Current/future information in historical rows causes data leakage.",
        "metrics": metrics,
    }
    return {"pipeline": pipe, "metadata": metadata}, metrics


def predict_exploitation(bundle: dict[str, Any], df: pd.DataFrame) -> pd.DataFrame:
    if not bundle or "pipeline" not in bundle:
        raise ValueError("No trained RiskBridge ML model is loaded.")
    features = prepare_ml_features(df)
    pipe: Pipeline = bundle["pipeline"]
    probabilities = pipe.predict_proba(features[NUMERIC_FEATURES + CATEGORICAL_FEATURES])[:, 1]
    result = df.copy()
    result["ml_exploitation_probability"] = probabilities
    result["ml_model_name"] = bundle.get("metadata", {}).get("model_name", "RiskBridge ML")
    return result


def explain_prediction(bundle: dict[str, Any], row: pd.Series | dict, top_n: int = 6) -> list[tuple[str, float]]:
    """Return largest logistic-regression log-odds contributions for one observation."""
    pipe: Pipeline = bundle["pipeline"]
    sample = prepare_ml_features(pd.DataFrame([dict(row)]))
    prep = pipe.named_steps["preprocessor"]
    model: LogisticRegression = pipe.named_steps["model"]
    transformed = prep.transform(sample[NUMERIC_FEATURES + CATEGORICAL_FEATURES])
    values = transformed.toarray()[0] if hasattr(transformed, "toarray") else np.asarray(transformed)[0]
    names = prep.get_feature_names_out()
    coef = model.coef_[0]
    contributions = [(str(name), float(value * weight)) for name, value, weight in zip(names, values, coef)]
    contributions.sort(key=lambda item: abs(item[1]), reverse=True)
    return contributions[:top_n]


def save_model(bundle: dict[str, Any], path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)


def load_model(path: str | Path) -> dict[str, Any]:
    return joblib.load(path)


def model_to_bytes(bundle: dict[str, Any]) -> bytes:
    buffer = io.BytesIO()
    joblib.dump(bundle, buffer)
    return buffer.getvalue()


def model_from_bytes(value: bytes) -> dict[str, Any]:
    return joblib.load(io.BytesIO(value))

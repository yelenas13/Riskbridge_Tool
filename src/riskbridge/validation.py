from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score


def _precision_at_k(y: np.ndarray, score: np.ndarray, k: int) -> float:
    k = max(1, min(k, len(y)))
    order = np.argsort(score)[::-1][:k]
    return float(np.mean(y[order])) if len(order) else 0.0


def compare_rankings(df: pd.DataFrame, target: str = "exploited_within_30d") -> pd.DataFrame:
    if target not in df.columns:
        raise ValueError(f"Validation data requires '{target}'.")
    work = df.copy()
    y = pd.to_numeric(work[target], errors="coerce")
    mask = y.isin([0, 1])
    work, y = work.loc[mask], y.loc[mask].astype(int).to_numpy()
    if len(work) < 5 or len(np.unique(y)) < 2:
        raise ValueError("Validation requires at least 5 labeled rows with both classes.")

    candidates = {
        "CVSS": pd.to_numeric(work.get("cvss_score"), errors="coerce").fillna(0).to_numpy() / 10.0,
        "EPSS": pd.to_numeric(work.get("epss"), errors="coerce").fillna(0).to_numpy(),
        "RiskBridge": pd.to_numeric(work.get("riskbridge_score"), errors="coerce").fillna(0).to_numpy() / 100.0,
    }
    if "ml_exploitation_probability" in work.columns:
        candidates["RiskBridge ML"] = pd.to_numeric(work["ml_exploitation_probability"], errors="coerce").fillna(0).to_numpy()

    rows = []
    for name, score in candidates.items():
        rows.append(
            {
                "ranking": name,
                "pr_auc": round(float(average_precision_score(y, score)), 6),
                "precision_at_10": round(_precision_at_k(y, score, min(10, len(y))), 6),
                "precision_at_50": round(_precision_at_k(y, score, min(50, len(y))), 6),
            }
        )
    return pd.DataFrame(rows).sort_values("pr_auc", ascending=False).reset_index(drop=True)

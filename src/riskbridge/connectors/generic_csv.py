from __future__ import annotations

from pathlib import Path
import pandas as pd

FINDING_REQUIRED = {"asset_id", "cve_id"}
ASSET_REQUIRED = {"asset_id", "hostname"}


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out.columns = [str(c).strip().lower() for c in out.columns]
    return out


def load_findings(path: str | Path) -> pd.DataFrame:
    df = _normalize_columns(pd.read_csv(path))
    missing = FINDING_REQUIRED - set(df.columns)
    if missing:
        raise ValueError(f"Findings CSV missing required columns: {', '.join(sorted(missing))}")
    df["cve_id"] = df["cve_id"].astype(str).str.upper().str.strip()
    if "product" not in df.columns:
        df["product"] = ""
    if "finding_id" not in df.columns:
        df["finding_id"] = [f"F-{i+1:05d}" for i in range(len(df))]
    return df


def load_assets(path: str | Path) -> pd.DataFrame:
    df = _normalize_columns(pd.read_csv(path))
    missing = ASSET_REQUIRED - set(df.columns)
    if missing:
        raise ValueError(f"Assets CSV missing required columns: {', '.join(sorted(missing))}")
    return df

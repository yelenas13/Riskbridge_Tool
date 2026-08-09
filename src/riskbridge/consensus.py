from __future__ import annotations

import pandas as pd


def normalize_vendor_scores(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize optional third-party scanner scores to 0-100 without changing RiskBridge scoring."""
    if df is None or df.empty:
        return pd.DataFrame()
    out = df.copy()
    out.columns = [str(c).strip().lower() for c in out.columns]
    required = {"cve_id", "vendor", "vendor_score"}
    missing = required - set(out.columns)
    if missing:
        raise ValueError(f"Vendor score CSV missing: {', '.join(sorted(missing))}")
    out["vendor_score"] = pd.to_numeric(out["vendor_score"], errors="coerce")
    if "scale_max" in out.columns:
        scale = pd.to_numeric(out["scale_max"], errors="coerce").replace(0, pd.NA)
        out["vendor_score_0_100"] = out["vendor_score"] / scale * 100.0
    else:
        # Conservative convention: values <=10 are assumed 0-10; values >10 are assumed 0-100.
        out["vendor_score_0_100"] = out["vendor_score"].where(out["vendor_score"] > 10, out["vendor_score"] * 10)
    out["vendor_score_0_100"] = out["vendor_score_0_100"].clip(0, 100)
    out["cve_id"] = out["cve_id"].astype(str).str.upper().str.strip()
    return out


def consensus_summary(df: pd.DataFrame) -> pd.DataFrame:
    norm = normalize_vendor_scores(df)
    if norm.empty:
        return pd.DataFrame()
    keys = ["cve_id"] + (["asset_id"] if "asset_id" in norm.columns else [])
    grouped = norm.groupby(keys)["vendor_score_0_100"].agg(["median", "min", "max", "count"]).reset_index()
    grouped["vendor_disagreement"] = grouped["max"] - grouped["min"]
    return grouped.rename(columns={"median": "vendor_consensus_0_100", "count": "vendor_count"})

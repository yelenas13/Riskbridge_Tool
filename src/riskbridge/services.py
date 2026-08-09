from __future__ import annotations

import pandas as pd


def business_service_summary(scored: pd.DataFrame, zero_day: pd.DataFrame | None = None) -> pd.DataFrame:
    if scored is None or scored.empty or "business_service" not in scored.columns:
        return pd.DataFrame()
    work = scored.copy()
    work["business_service"] = work["business_service"].fillna("Unassigned").replace("", "Unassigned")
    summary = (
        work.groupby("business_service")
        .agg(
            findings=("cve_id", "count"),
            unique_cves=("cve_id", "nunique"),
            assets=("asset_id", "nunique"),
            max_risk=("riskbridge_score", "max"),
            avg_risk=("riskbridge_score", "mean"),
            avg_confidence=("confidence", "mean"),
            p0=("priority", lambda s: int((s == "P0").sum())),
            p1=("priority", lambda s: int((s == "P1").sum())),
        )
        .reset_index()
    )
    if zero_day is not None and not zero_day.empty and "business_service" in zero_day.columns:
        zd = (
            zero_day.groupby("business_service")["zero_day_exposure_score"]
            .max()
            .rename("max_zero_day_exposure")
            .reset_index()
        )
        summary = summary.merge(zd, on="business_service", how="left")
    return summary.sort_values(["max_risk", "p0", "p1"], ascending=[False, False, False]).reset_index(drop=True)

from __future__ import annotations

from pathlib import Path
import pandas as pd

from .intelligence import enrich_cves
from .policy import apply_policy
from .scoring import score_finding
from .zero_day import zero_day_exposure


def _prefer(existing, incoming):
    if existing is None or (isinstance(existing, float) and pd.isna(existing)) or str(existing).strip() == "":
        return incoming
    return existing


def merge_intelligence(findings: pd.DataFrame, live: bool, cache_dir: str = ".riskbridge_cache") -> pd.DataFrame:
    df = findings.copy()
    if not live:
        return df
    intel = enrich_cves(df["cve_id"].dropna().astype(str).tolist(), cache_dir)
    for idx, row in df.iterrows():
        cid = str(row.get("cve_id", "")).upper()
        data = intel.get(cid, {})
        for key, value in data.items():
            if key == "cve_id":
                continue
            if key not in df.columns:
                df[key] = None
            df.at[idx, key] = _prefer(row.get(key), value)
    return df


def run_analysis(findings: pd.DataFrame, assets: pd.DataFrame, config: dict, *, live: bool = False,
                 cache_dir: str = ".riskbridge_cache") -> tuple[pd.DataFrame, pd.DataFrame]:
    enriched = merge_intelligence(findings, live=live, cache_dir=cache_dir)
    merged = enriched.merge(assets, on="asset_id", how="left", suffixes=("", "_asset"))

    scored_rows = []
    for _, row in merged.iterrows():
        base = row.to_dict()
        scoring = score_finding(row, config)
        base.update(scoring)
        base.update(apply_policy(base, config))
        scored_rows.append(base)
    scored = pd.DataFrame(scored_rows)
    if not scored.empty:
        scored = scored.sort_values(["riskbridge_score", "confidence"], ascending=[False, False]).reset_index(drop=True)

    zd_rows = []
    for _, row in assets.iterrows():
        base = row.to_dict()
        base.update(zero_day_exposure(row, config))
        zd_rows.append(base)
    zero_day = pd.DataFrame(zd_rows)
    if not zero_day.empty:
        zero_day = zero_day.sort_values("zero_day_exposure_score", ascending=False).reset_index(drop=True)
    return scored, zero_day

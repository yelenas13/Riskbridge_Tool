from __future__ import annotations

import pandas as pd

from .applicability import assess_applicability
from .detection import detection_guidance
from .exceptions import evaluate_exception
from .intelligence import enrich_cves
from .ml import predict_exploitation
from .policy import apply_policy
from .remediation import remediation_guidance
from .scoring import score_finding
from .zero_day import zero_day_exposure


def _usable(value) -> bool:
    if value is None:
        return False
    if isinstance(value, float) and pd.isna(value):
        return False
    if isinstance(value, str) and not value.strip():
        return False
    return True


def merge_intelligence(
    findings: pd.DataFrame,
    live: bool,
    cache_dir: str = ".riskbridge_cache",
    *,
    include_epss_history: bool = False,
) -> pd.DataFrame:
    df = findings.copy()
    if not live:
        return df
    intel = enrich_cves(
        df["cve_id"].dropna().astype(str).tolist(),
        cache_dir,
        include_epss_history=include_epss_history,
    )
    for idx, row in df.iterrows():
        cid = str(row.get("cve_id", "")).upper()
        data = intel.get(cid, {})
        for key, value in data.items():
            if key == "cve_id" or not _usable(value):
                continue
            if key not in df.columns:
                df[key] = None
            # Live public intelligence is treated as the source of truth for these enrichment
            # fields. Scanner-native scores should be preserved in separate vendor columns.
            df.at[idx, key] = value
    return df


def run_analysis(
    findings: pd.DataFrame,
    assets: pd.DataFrame,
    config: dict,
    *,
    live: bool = False,
    cache_dir: str = ".riskbridge_cache",
    include_epss_history: bool = False,
    ml_bundle: dict | None = None,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    enriched = merge_intelligence(
        findings,
        live=live,
        cache_dir=cache_dir,
        include_epss_history=include_epss_history,
    )
    merged = enriched.merge(assets, on="asset_id", how="left", suffixes=("", "_asset"))

    contextual_rows: list[dict] = []
    for _, row in merged.iterrows():
        base = row.to_dict()
        if not str(base.get("product") or "").strip():
            base["product"] = base.get("asset_product") or base.get("primary_affected_product") or "unknown-product"
        base.update(assess_applicability(pd.Series(base)))
        base.update(detection_guidance(pd.Series(base)))
        contextual_rows.append(base)
    contextual = pd.DataFrame(contextual_rows)

    if ml_bundle is not None and not contextual.empty:
        contextual = predict_exploitation(ml_bundle, contextual)

    scored_rows: list[dict] = []
    for _, row in contextual.iterrows():
        base = row.to_dict()
        # Remediation uses applicability and source evidence.
        base.update(remediation_guidance(pd.Series(base)))
        base.update(evaluate_exception(pd.Series(base)))
        base.update(score_finding(pd.Series(base), config))
        base.update(apply_policy(base, config))

        if base.get("priority") == "NA":
            base["decision_status"] = "NOT APPLICABLE — VERIFY"
        elif base.get("exception_active"):
            base["decision_status"] = "ACTIVE EXCEPTION"
        else:
            base["decision_status"] = "REMEDIATE / MITIGATE"
        scored_rows.append(base)

    scored = pd.DataFrame(scored_rows)
    if not scored.empty:
        priority_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "NA": 4}
        scored["_priority_order"] = scored["priority"].map(priority_order).fillna(9)
        scored = scored.sort_values(
            ["_priority_order", "riskbridge_score", "confidence"],
            ascending=[True, False, False],
        ).drop(columns=["_priority_order"]).reset_index(drop=True)

    zd_rows = []
    for _, row in assets.iterrows():
        base = row.to_dict()
        base.update(zero_day_exposure(row, config))
        zd_rows.append(base)
    zero_day = pd.DataFrame(zd_rows)
    if not zero_day.empty:
        zero_day = zero_day.sort_values("zero_day_exposure_score", ascending=False).reset_index(drop=True)
    return scored, zero_day

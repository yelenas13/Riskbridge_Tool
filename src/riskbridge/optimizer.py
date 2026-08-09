from __future__ import annotations

import pandas as pd


def optimize_patch_bundles(scored: pd.DataFrame, weekly_hours: float | None = None) -> pd.DataFrame:
    if scored.empty:
        return pd.DataFrame()

    actions: dict[str, dict] = {}
    for _, row in scored.iterrows():
        product = str(row.get("product") or "unknown-product")
        hours = float(row.get("remediation_hours") or 2.0)
        key = product
        item = actions.setdefault(key, {"action": f"Remediate {product}", "product": product,
                                        "cves": set(), "risk_removed": 0.0, "hours": 0.0})
        if row.get("cve_id"):
            item["cves"].add(str(row.get("cve_id")))
        item["risk_removed"] += float(row.get("riskbridge_score") or 0.0)
        item["hours"] += max(0.25, hours)

    rows = []
    for item in actions.values():
        rows.append({
            "action": item["action"],
            "product": item["product"],
            "cves": ", ".join(sorted(item["cves"])),
            "risk_points_removed": round(item["risk_removed"], 2),
            "estimated_hours": round(item["hours"], 2),
            "risk_points_per_hour": round(item["risk_removed"] / item["hours"], 2) if item["hours"] else 0,
        })
    result = pd.DataFrame(rows).sort_values("risk_points_per_hour", ascending=False).reset_index(drop=True)

    if weekly_hours is not None:
        remaining = float(weekly_hours)
        selected = []
        for _, row in result.iterrows():
            use = float(row["estimated_hours"])
            if use <= remaining:
                selected.append("THIS WEEK")
                remaining -= use
            else:
                selected.append("BACKLOG")
        result["schedule"] = selected
    return result

from __future__ import annotations

from pathlib import Path
import json
import pandas as pd

from .optimizer import optimize_patch_bundles
from .services import business_service_summary


def _decision_cards(scored: pd.DataFrame) -> list[dict]:
    cards: list[dict] = []
    for _, row in scored.iterrows():
        cards.append(
            {
                "cve_id": row.get("cve_id"),
                "asset_id": row.get("asset_id"),
                "hostname": row.get("hostname"),
                "priority": row.get("priority"),
                "riskbridge_score": row.get("riskbridge_score"),
                "confidence": row.get("confidence"),
                "description": row.get("description_short") or row.get("description"),
                "applicability_status": row.get("applicability_status"),
                "applicability_reason": row.get("applicability_reason"),
                "affected_products": row.get("affected_products_nvd"),
                "where_to_look": row.get("where_to_look"),
                "verification_commands": row.get("verification_commands"),
                "remediation": row.get("remediation_primary"),
                "remediation_secondary": row.get("remediation_secondary"),
                "remediation_confidence": row.get("remediation_confidence"),
                "patch_by": row.get("patch_by"),
                "decision_status": row.get("decision_status"),
                "top_risk_drivers": row.get("top_risk_drivers"),
                "nvd_url": row.get("nvd_url"),
                "advisory_urls": row.get("advisory_urls"),
                "provenance": row.get("provenance"),
            }
        )
    return cards


def export_outputs(
    scored: pd.DataFrame,
    zero_day: pd.DataFrame,
    output_dir: str | Path,
    weekly_hours: float | None = None,
) -> dict[str, str]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    optimizer = optimize_patch_bundles(scored, weekly_hours=weekly_hours)
    services = business_service_summary(scored, zero_day)

    csv_scored = out / "prioritized_vulnerabilities.csv"
    csv_zd = out / "zero_day_exposure.csv"
    csv_opt = out / "remediation_optimizer.csv"
    csv_services = out / "business_service_risk.csv"
    xlsx = out / "riskbridge_report.xlsx"
    json_summary = out / "riskbridge_summary.json"
    json_cards = out / "decision_cards.json"

    scored.to_csv(csv_scored, index=False)
    zero_day.to_csv(csv_zd, index=False)
    optimizer.to_csv(csv_opt, index=False)
    services.to_csv(csv_services, index=False)

    with pd.ExcelWriter(xlsx, engine="openpyxl") as writer:
        scored.to_excel(writer, sheet_name="Prioritized CVEs", index=False)
        zero_day.to_excel(writer, sheet_name="Zero-Day Exposure", index=False)
        optimizer.to_excel(writer, sheet_name="Remediation Plan", index=False)
        services.to_excel(writer, sheet_name="Business Services", index=False)

    summary = {
        "findings": int(len(scored)),
        "p0": int((scored.get("priority") == "P0").sum()) if not scored.empty else 0,
        "p1": int((scored.get("priority") == "P1").sum()) if not scored.empty else 0,
        "not_applicable": int((scored.get("priority") == "NA").sum()) if not scored.empty else 0,
        "average_riskbridge_score": round(float(scored["riskbridge_score"].mean()), 2) if not scored.empty else 0,
        "average_confidence": round(float(scored["confidence"].mean()), 2) if not scored.empty else 0,
        "critical_zero_day_assets": int((zero_day.get("zero_day_exposure_rating") == "CRITICAL").sum()) if not zero_day.empty else 0,
        "high_zero_day_assets": int((zero_day.get("zero_day_exposure_rating") == "HIGH").sum()) if not zero_day.empty else 0,
    }
    json_summary.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    json_cards.write_text(json.dumps(_decision_cards(scored), indent=2, default=str), encoding="utf-8")
    return {
        "prioritized_csv": str(csv_scored),
        "zero_day_csv": str(csv_zd),
        "optimizer_csv": str(csv_opt),
        "business_service_csv": str(csv_services),
        "excel": str(xlsx),
        "summary": str(json_summary),
        "decision_cards": str(json_cards),
    }

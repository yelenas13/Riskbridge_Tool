from __future__ import annotations

from pathlib import Path
import json
import pandas as pd

from .optimizer import optimize_patch_bundles


def export_outputs(scored: pd.DataFrame, zero_day: pd.DataFrame, output_dir: str | Path,
                   weekly_hours: float | None = None) -> dict[str, str]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    optimizer = optimize_patch_bundles(scored, weekly_hours=weekly_hours)

    csv_scored = out / "prioritized_vulnerabilities.csv"
    csv_zd = out / "zero_day_exposure.csv"
    csv_opt = out / "remediation_optimizer.csv"
    xlsx = out / "riskbridge_report.xlsx"
    json_summary = out / "riskbridge_summary.json"

    scored.to_csv(csv_scored, index=False)
    zero_day.to_csv(csv_zd, index=False)
    optimizer.to_csv(csv_opt, index=False)

    with pd.ExcelWriter(xlsx, engine="openpyxl") as writer:
        scored.to_excel(writer, sheet_name="Prioritized CVEs", index=False)
        zero_day.to_excel(writer, sheet_name="Zero-Day Exposure", index=False)
        optimizer.to_excel(writer, sheet_name="Remediation Plan", index=False)

    summary = {
        "findings": int(len(scored)),
        "p0": int((scored.get("priority") == "P0").sum()) if not scored.empty else 0,
        "p1": int((scored.get("priority") == "P1").sum()) if not scored.empty else 0,
        "average_riskbridge_score": round(float(scored["riskbridge_score"].mean()), 2) if not scored.empty else 0,
        "critical_zero_day_assets": int((zero_day.get("zero_day_exposure_rating") == "CRITICAL").sum()) if not zero_day.empty else 0,
        "high_zero_day_assets": int((zero_day.get("zero_day_exposure_rating") == "HIGH").sum()) if not zero_day.empty else 0,
    }
    json_summary.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return {
        "prioritized_csv": str(csv_scored),
        "zero_day_csv": str(csv_zd),
        "optimizer_csv": str(csv_opt),
        "excel": str(xlsx),
        "summary": str(json_summary),
    }

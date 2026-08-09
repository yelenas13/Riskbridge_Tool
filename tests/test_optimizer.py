import pandas as pd

from riskbridge.optimizer import optimize_patch_bundles


def test_optimizer_orders_by_risk_per_hour():
    df = pd.DataFrame([
        {"product": "A", "cve_id": "CVE-1", "riskbridge_score": 90, "remediation_hours": 9},
        {"product": "B", "cve_id": "CVE-2", "riskbridge_score": 70, "remediation_hours": 2},
    ])
    result = optimize_patch_bundles(df)
    assert result.iloc[0]["product"] == "B"

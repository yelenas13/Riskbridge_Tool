import pandas as pd

from riskbridge.remediation import remediation_guidance


def test_kev_required_action_is_primary_when_present():
    result = remediation_guidance(pd.Series({
        "applicability_status": "CONFIRMED",
        "kev_required_action": "Apply mitigations per vendor instructions or discontinue use.",
        "known_exploited": True,
    }))
    assert result["remediation_primary"].startswith("Apply mitigations")
    assert result["remediation_source"] == "CISA KEV requiredAction"
    assert result["remediation_confidence"] == "HIGH"

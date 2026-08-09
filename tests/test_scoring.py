import pandas as pd

from riskbridge.scoring import score_finding


CONFIG = {
    "scoring": {
        "weights": {"technical": 0.20, "threat": 0.30, "business": 0.30, "exposure": 0.20},
        "control_mitigation_cap": 0.35,
    }
}


def base_row():
    return {
        "cvss_score": 9.8,
        "epss": 0.90,
        "epss_percentile": 0.99,
        "known_exploited": True,
        "environment": "production",
        "criticality": 5,
        "data_sensitivity": 5,
        "revenue_impact": 5,
        "safety_impact": 2,
        "internet_exposed": True,
        "privileged": True,
        "public_api": True,
        "remote_access": False,
        "network_reachability": 5,
        "open_ports": 8,
        "segmentation_effectiveness": 2,
        "edr_effectiveness": 3,
        "waf_effectiveness": 2,
        "least_privilege_effectiveness": 2,
        "monitoring_effectiveness": 4,
    }


def test_high_context_finding_is_prioritized():
    result = score_finding(pd.Series(base_row()), CONFIG)
    assert result["riskbridge_score"] >= 70
    assert result["priority"] in {"P0", "P1"}
    assert result["confidence"] == 100.0


def test_stronger_controls_reduce_residual_score():
    weak = base_row()
    strong = base_row()
    for key in ["segmentation_effectiveness", "edr_effectiveness", "waf_effectiveness",
                "least_privilege_effectiveness", "monitoring_effectiveness"]:
        strong[key] = 5
    weak_result = score_finding(pd.Series(weak), CONFIG)
    strong_result = score_finding(pd.Series(strong), CONFIG)
    assert strong_result["riskbridge_score"] < weak_result["riskbridge_score"]


def test_missing_data_reduces_confidence_not_randomizes():
    row = base_row()
    row["epss"] = None
    row["epss_percentile"] = None
    result = score_finding(pd.Series(row), CONFIG)
    assert result["confidence"] < 100.0
    assert "EPSS" in result["data_gaps"]

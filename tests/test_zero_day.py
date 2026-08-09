import pandas as pd

from riskbridge.zero_day import zero_day_exposure

CONFIG = {"zero_day": {"weights": {
    "attack_surface": 0.25,
    "privilege_reachability": 0.20,
    "software_exposure": 0.20,
    "business_impact": 0.25,
    "control_weakness": 0.10,
}}}


def test_zero_day_model_does_not_need_cve_data():
    asset = pd.Series({
        "environment": "production",
        "criticality": 5,
        "data_sensitivity": 5,
        "revenue_impact": 5,
        "safety_impact": 3,
        "internet_exposed": True,
        "privileged": True,
        "network_reachability": 5,
        "identity_criticality": 4,
        "open_ports": 10,
        "public_api": True,
        "remote_access": True,
        "unsupported_software": True,
        "technology_age_years": 8,
        "third_party_exposure": True,
        "segmentation_effectiveness": 1,
        "edr_effectiveness": 2,
        "waf_effectiveness": 1,
        "least_privilege_effectiveness": 2,
        "monitoring_effectiveness": 2,
    })
    result = zero_day_exposure(asset, CONFIG)
    assert result["zero_day_exposure_score"] >= 70
    assert result["zero_day_exposure_rating"] in {"HIGH", "CRITICAL"}

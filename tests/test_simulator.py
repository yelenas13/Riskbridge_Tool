import pandas as pd

from riskbridge.simulator import simulate_interventions

CONFIG = {
    "scoring": {
        "weights": {"technical": .2, "threat": .3, "business": .3, "exposure": .2},
        "threat_weights": {"epss": .35, "percentile": .15, "kev": .25, "velocity": .10, "ml": .15},
        "control_mitigation_cap": .35,
    },
    "simulator": {"effort_hours": {"patch": 2, "remove_internet_exposure": 2, "segmentation": 4,
                                      "least_privilege": 3, "edr": 2, "waf": 2}},
}


def test_patch_scenario_removes_specific_finding():
    row = pd.Series({
        "cvss_score": 9.8, "epss": .8, "epss_percentile": .98, "known_exploited": True,
        "criticality": 5, "data_sensitivity": 5, "revenue_impact": 5, "safety_impact": 1,
        "environment": "production", "internet_exposed": True, "privileged": False,
        "public_api": True, "remote_access": False, "network_reachability": 4, "open_ports": 5,
        "segmentation_effectiveness": 2, "edr_effectiveness": 3, "waf_effectiveness": 2,
        "least_privilege_effectiveness": 3, "monitoring_effectiveness": 3,
        "applicability_status": "CONFIRMED", "remediation_hours": 2,
    })
    result = simulate_interventions(row, CONFIG)
    patch = result[result["action"].str.startswith("Patch")].iloc[0]
    assert patch["resulting_risk"] == 0
    assert patch["risk_reduction"] > 0

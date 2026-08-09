import pandas as pd

from riskbridge.attack_paths import exposure_paths


def test_structural_path_to_crown_jewel():
    assets = pd.DataFrame([
        {"asset_id": "A", "hostname": "edge", "internet_exposed": True, "criticality": 3, "identity_criticality": 1},
        {"asset_id": "B", "hostname": "idp", "internet_exposed": False, "criticality": 5, "identity_criticality": 5},
    ])
    rel = pd.DataFrame([{"from_asset": "A", "to_asset": "B", "relationship": "reachable"}])
    scored = pd.DataFrame([{"asset_id": "A", "riskbridge_score": 70}, {"asset_id": "B", "riskbridge_score": 80}])
    zd = pd.DataFrame([{"asset_id": "A", "zero_day_exposure_score": 60}, {"asset_id": "B", "zero_day_exposure_score": 75}])
    result = exposure_paths(assets, rel, scored, zd)
    assert len(result) == 1
    assert "STRUCTURAL PATH" in result.iloc[0]["verification"]

import json
import pandas as pd

from riskbridge.applicability import assess_applicability


def row(version):
    matches = [{
        "vendor": "acme",
        "product": "widget",
        "version": "*",
        "version_start_including": "1.0.0",
        "version_end_excluding": "2.0.0",
    }]
    return pd.Series({
        "asset_vendor": "Acme",
        "asset_product": "Widget",
        "asset_version": version,
        "cpe_matches_json": json.dumps(matches),
    })


def test_confirmed_version_in_range():
    result = assess_applicability(row("1.5.0"))
    assert result["applicability_status"] == "CONFIRMED"
    assert result["applicability_confidence"] == 100


def test_out_of_range_version_is_not_assumed_vulnerable():
    result = assess_applicability(row("2.1.0"))
    assert result["applicability_status"] == "OUT_OF_RANGE"
    assert not result["applicability_assumes_affected"]

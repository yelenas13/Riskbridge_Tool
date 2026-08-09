import pandas as pd

from riskbridge.ml import train_exploitation_model, predict_exploitation


def make_training_data(n=60):
    rows = []
    start = pd.Timestamp("2025-01-01", tz="UTC")
    for i in range(n):
        positive = 1 if i % 4 == 0 or i % 7 == 0 else 0
        rows.append({
            "observation_date": (start + pd.Timedelta(days=i)).isoformat(),
            "published": (start - pd.Timedelta(days=20 + i % 10)).isoformat(),
            "cve_id": f"CVE-2025-{1000+i}",
            "cvss_score": 9.2 if positive else 6.1,
            "epss": .75 if positive else .08,
            "epss_percentile": .96 if positive else .45,
            "epss_delta_7d": .2 if positive else .01,
            "epss_delta_30d": .35 if positive else .03,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if positive else "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L",
            "cwe": "CWE-78" if positive else "CWE-200",
            "exploited_within_30d": positive,
        })
    return pd.DataFrame(rows)


def test_real_ml_pipeline_trains_with_chronological_holdout():
    data = make_training_data()
    bundle, metrics = train_exploitation_model(data)
    assert bundle["metadata"]["model_type"] == "LogisticRegression"
    assert metrics["train_rows"] < metrics["rows"]
    pred = predict_exploitation(bundle, data.tail(2))
    assert pred["ml_exploitation_probability"].between(0, 1).all()

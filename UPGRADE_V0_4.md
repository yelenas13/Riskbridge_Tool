# Upgrade Riskbridge_Tool to v0.4

`app.py` alone is not enough because v0.4 adds backend modules and dependencies.

## Replace these existing files
- `app.py`
- `requirements.txt`
- `pyproject.toml`
- `config/default.yaml`
- `README.md`
- `src/riskbridge/intelligence.py`
- `src/riskbridge/scoring.py`
- `src/riskbridge/zero_day.py`
- `src/riskbridge/pipeline.py`
- `src/riskbridge/policy.py`
- `src/riskbridge/reporting.py`
- `src/riskbridge/cli.py`
- `src/riskbridge/connectors/generic_csv.py`
- `docs/DATA_SCHEMA.md`
- `docs/INTEGRATIONS.md`
- `docs/MODEL.md`
- `examples/assets.csv`
- `examples/findings.csv`
- `tests/test_scoring.py`
- `tests/test_zero_day.py`

## Add these new files
- `src/riskbridge/applicability.py`
- `src/riskbridge/detection.py`
- `src/riskbridge/remediation.py`
- `src/riskbridge/ml.py`
- `src/riskbridge/simulator.py`
- `src/riskbridge/exceptions.py`
- `src/riskbridge/consensus.py`
- `src/riskbridge/services.py`
- `src/riskbridge/attack_paths.py`
- `src/riskbridge/validation.py`
- `docs/ML_MODEL_CARD.md`
- `docs/REMEDIATION_AND_APPLICABILITY.md`
- `examples/relationships.csv`
- `examples/vendor_scores.csv`
- `examples/ml_training_template.csv`
- `tests/test_applicability.py`
- `tests/test_remediation.py`
- `tests/test_simulator.py`
- `tests/test_ml.py`
- `tests/test_attack_paths.py`
- `UPGRADE_V0_4.md`

## Validate locally

```powershell
git pull
.\riskenv\Scripts\Activate.ps1
pip install -e ".[dev]"
python -m pytest -q
streamlit run app.py
```

Expected backend test result: `12 passed`.

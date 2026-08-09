# RiskBridge Emerging Exploitation Model (REEM) — Model Card

## Purpose
REEM estimates a threat signal for a **published CVE**. It is not a zero-day predictor and it does not directly assign P0/P1/P2/P3. Its output is one optional input to the RiskBridge Threat dimension.

## Baseline model
- Algorithm: Logistic Regression
- Class weighting: balanced
- Holdout: chronological 80/20 split
- Target: `exploited_within_30d`
- Minimum training rows enforced by code: 30, with both classes represented

## Features
Numeric:
- CVSS score
- EPSS probability
- EPSS percentile
- EPSS 7-day delta
- EPSS 30-day delta
- days since publication at observation time

Categorical (derived):
- CVSS attack vector
- attack complexity
- privileges required
- user interaction
- scope
- primary CWE

## Required governance
Training rows must be point-in-time snapshots. A historical row must contain only information that was available on its `observation_date`.

Do not use future KEV membership, later EPSS values, future exploit evidence, or later asset context as historical features. That creates leakage and invalidates the evaluation.

## Evaluation
The training function records:
- PR-AUC
- ROC-AUC where valid
- Brier score
- Precision@10
- train/test date ranges
- train/test row counts

The Validation Lab can compare CVSS, EPSS, RiskBridge, and REEM when labeled data is available.

## Explainability
For Logistic Regression, RiskBridge can show the largest per-observation log-odds feature contributions. These are model contributions, not causal explanations.

## Deployment rule
Riskbridge_Tool ships **without a pre-trained REEM artifact**. A model is used only after the user trains/uploads a model. This prevents the repository from presenting unvalidated synthetic training as production intelligence.

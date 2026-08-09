# RiskBridge v0.4 Model

## Known-CVE decision model
RiskBridge separates dimensions before computing residual risk:

- Technical: CVSS
- Threat: EPSS probability, EPSS percentile, KEV, EPSS velocity, optional REEM ML signal
- Business: criticality, data sensitivity, revenue/safety impact, environment
- Exposure: internet exposure, privilege, API/remote access, reachability, open services
- Controls: segmentation, EDR, WAF, least privilege, monitoring

Default base weights are configurable in `config/default.yaml`.

Controls reduce base risk only up to the configured mitigation cap. This is a model assumption, not an empirical guarantee of loss reduction.

## Applicability
`OUT_OF_RANGE` findings are assigned `NA` and a final risk of 0 for that asset/CVE decision, while the conditional risk is retained for auditability. Product mismatch alone is not considered proof of non-applicability.

## Confidence
Confidence is separate from risk and considers data availability/freshness, applicability evidence, remediation evidence, business/exposure/control context, EPSS trend, and intelligence errors.

## Emerging vulnerability
A disclosed-CVE emerging score uses CVSS, EPSS, percentile, recency, velocity, and optional REEM. It is not a zero-day prediction.

## Pre-CVE model
Zero-Day Exposure measures asset exposure independently of a CVE. Zero-Day Preparedness measures response readiness. The response gap highlights assets with high exposure and relatively weak preparedness.

## Decision optimization
The What-If Simulator and patch optimizer use RiskBridge risk points. They do not manufacture financial loss. Organizations may later add defensible financial impact data as a separate model.

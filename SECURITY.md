# Security Policy

Riskbridge_Tool is a prioritization and decision-support application. It is not a vulnerability scanner, exploit framework, or substitute for professional engineering/risk judgment.

## Reporting a vulnerability
Report security issues privately to the repository owner rather than opening a public issue. Do not include production credentials, proprietary inventories, or sensitive scan exports in public issues.

## Data handling
- Public-data mode uses NVD, FIRST EPSS, and CISA KEV only when live enrichment is requested.
- Uploaded organization CSV/YAML data is processed by the running application.
- Never commit real organization inventories, vulnerability exports, credentials, tokens, API keys, or generated reports to a public repository.
- YAML is parsed with `safe_load`.

## ML artifact safety
Python pickle/joblib artifacts are executable serialization formats and must be treated as trusted code.

- The public Streamlit UI **does not deserialize user-uploaded `.joblib` or `.pkl` models**.
- The ML Lab trains a model from uploaded CSV observations inside the current session.
- CLI model loading is intended only for model files controlled by the operator. Do not load an untrusted model file.

## Defensive scope
“Where to look” commands are inventory/verification commands. Riskbridge_Tool does not provide exploit execution or persistence capabilities.

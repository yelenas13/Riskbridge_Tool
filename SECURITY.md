# Security Policy

RiskBridge is a prioritization and decision-support tool. It is not a vulnerability scanner,
exploit framework, or substitute for professional risk judgment.

## Reporting a vulnerability

Please report security issues privately to the repository owner rather than opening a public issue.
Do not include production credentials, proprietary asset inventories, or sensitive scan exports in public issues.

## Data handling

- RiskBridge does not require credentials for its default public-data mode.
- NVD, FIRST EPSS, and CISA KEV are queried only when live enrichment is enabled.
- Organization CSV files are processed locally by the application.
- Never commit real organization inventories or scanner exports to a public repository.

# Integrations

Riskbridge_Tool is intentionally vendor-neutral. Integrations should normalize external findings into the common CSV/dataframe schema rather than putting vendor-specific logic into the scoring engine.

Planned adapter pattern:

```text
Qualys ─────┐
Tenable ────┤
Defender ───┼─> connector adapter ─> normalized finding + asset context ─> RiskBridge
Rapid7 ─────┤
CSV/JSON ───┘
```

## Adapter requirements
A connector should preserve, when available:
- scanner finding ID
- asset ID/hostname
- CVE
- product/version
- port/protocol
- first/last observed
- scanner-native score and score scale
- remediation evidence

Scanner-native scores should be kept as comparison evidence. Do not double-count them as if they were independent from CVSS/EPSS/KEV signals.

## Secrets
Do not commit API tokens. Future live connectors should use environment variables or a secrets manager and should document minimum required permissions.

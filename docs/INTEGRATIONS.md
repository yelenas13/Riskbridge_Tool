# Scanner Integration Strategy

RiskBridge should never make its scoring engine depend on a particular scanner.

## Integration contract

Every connector must produce the normalized findings schema described in `DATA_SCHEMA.md`.

A connector may preserve scanner-specific values in extra columns such as:

- `scanner`
- `scanner_finding_id`
- `scanner_risk_score`
- `scanner_status`
- `scanner_first_found`
- `scanner_last_found`

RiskBridge can display those values as corroborating evidence, but should not blindly add a vendor score to CVSS/EPSS/KEV
because vendor scores may already contain overlapping threat factors.

## Recommended order

1. Generic CSV — implemented now.
2. Qualys export/API adapter.
3. Tenable export/API adapter.
4. Microsoft Defender Vulnerability Management adapter.
5. Rapid7 / CrowdStrike exposure-management adapters as demand requires.

## Qualys design

When access becomes available, map Qualys host detections and asset context into RiskBridge. Keep QDS as a separate
`scanner_risk_score` for comparison rather than simply adding it to RiskBridge's threat score.

Example conceptual flow:

```text
Qualys Host Detection / VMDR
       ↓
Qualys connector
       ↓
RiskBridge common finding schema
       ↓
NVD + EPSS + KEV enrichment
       ↓
Business / asset context
       ↓
RiskBridge decision score
```

## Security

- Read API credentials from environment variables or a secrets manager.
- Never hard-code tokens.
- Do not commit real scan exports to GitHub.
- Log API errors without logging credentials.

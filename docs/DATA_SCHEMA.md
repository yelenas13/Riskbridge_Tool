# RiskBridge Data Schema

## Findings CSV

Required:

| Field | Meaning |
|---|---|
| `asset_id` | Asset identifier matching the asset inventory |
| `cve_id` | CVE identifier |
| `product` | Normalized product name |

Recommended:

- `finding_id`
- `port`
- `protocol`
- `first_seen`
- `remediation_hours`
- `cvss_score`
- `cvss_severity`
- `epss`
- `epss_percentile`
- `known_exploited`
- `published`
- `exposure_hint`

If live enrichment is enabled, CVSS/EPSS/KEV fields can be populated from public sources. Existing organization-supplied
values are preferred over public enrichment when present.

## Asset CSV

Required:

- `asset_id`
- `hostname`

Recommended 1-5 fields:

- `criticality`
- `data_sensitivity`
- `revenue_impact`
- `safety_impact`
- `network_reachability`
- `identity_criticality`
- `segmentation_effectiveness`
- `edr_effectiveness`
- `waf_effectiveness`
- `least_privilege_effectiveness`
- `monitoring_effectiveness`

Recommended boolean/context fields:

- `environment`
- `internet_exposed`
- `privileged`
- `public_api`
- `remote_access`
- `unsupported_software`
- `third_party_exposure`
- `open_ports`
- `technology_age_years`

### 1-5 convention

`1` means low/weak and `5` means high/strong. For controls, a high number means a more effective control. For impact and
reachability, a high number means greater impact/reach.

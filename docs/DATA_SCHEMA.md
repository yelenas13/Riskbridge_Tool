# RiskBridge v0.4 Data Schema

## Findings CSV
Required:
- `asset_id`
- `cve_id`

Recommended:
- `finding_id`
- `product` (`vendor:product` where possible)
- `installed_version`
- `port`
- `protocol`
- `first_seen`
- `remediation_hours`

Offline use may also provide CVSS/EPSS/KEV fields. With live enrichment, RiskBridge refreshes authoritative public intelligence when available.

## Asset inventory CSV
Required:
- `asset_id`
- `hostname`

Recommended business context:
- `business_service`
- `environment`
- `criticality` (1-5)
- `data_sensitivity` (1-5)
- `revenue_impact` (1-5)
- `safety_impact` (1-5)
- `crown_jewel` (boolean)

Applicability/inventory:
- `asset_vendor`
- `asset_product`
- `asset_version`
- `os_family`

Exposure:
- `internet_exposed`
- `privileged`
- `network_reachability` (1-5)
- `identity_criticality` (1-5)
- `open_ports`
- `public_api`
- `remote_access`
- `unsupported_software`
- `technology_age_years`
- `third_party_exposure`

Controls (1 weak → 5 strong):
- `segmentation_effectiveness`
- `edr_effectiveness`
- `waf_effectiveness`
- `least_privilege_effectiveness`
- `monitoring_effectiveness`

Zero-day preparedness (1 weak → 5 strong):
- `isolation_readiness`
- `emergency_patching_readiness`
- `recovery_readiness`
- `inventory_accuracy`
- `telemetry_readiness`
- `change_flexibility`

## Relationships CSV — Attack-Path Lite

```csv
from_asset,to_asset,relationship
A-001,A-005,remote-access-to-identity
```

The graph represents declared reachability/dependency only. It is not proof that a specific exploit path is traversable.

## Vendor score CSV

```csv
cve_id,vendor,vendor_score,scale_max
CVE-2024-XXXX,ScannerA,93,100
CVE-2024-XXXX,ScannerB,8.4,10
```

These scores are compared for consensus/disagreement and are not silently blended into the RiskBridge score.

## ML training CSV
Required:
- `observation_date`
- `exploited_within_30d` (0/1)
- `published`
- `cvss_score`
- `cvss_vector`
- `cwe`
- `epss`
- `epss_percentile`

Optional:
- `epss_delta_7d`
- `epss_delta_30d`

Historical rows must be point-in-time snapshots to avoid leakage.

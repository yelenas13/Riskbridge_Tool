# Applicability, Detection, and Remediation

## Applicability first
RiskBridge treats a manually entered CVE as a hypothesis until product/version evidence supports it.

Statuses:
- `CONFIRMED` — asset product/version matches an NVD vulnerable CPE/range.
- `POSSIBLE` — product matches but version is absent or cannot be reliably compared.
- `OUT_OF_RANGE` — matching product has a version explicitly outside listed NVD vulnerable ranges; verify vendor guidance before closure.
- `UNVERIFIED` — asset product does not match NVD names; this is not proof of safety.
- `UNKNOWN` — insufficient applicability data.

## Where to look
RiskBridge uses CPE/product context and user-entered OS family to produce defensive inventory checks for:
- software/package inventory
- SBOM/dependency inventory
- services
- container images
- operating-system builds
- hardware/firmware inventory

It intentionally avoids inventing exact filesystem paths.

## Remediation source hierarchy
RiskBridge prefers:
1. CISA KEV `requiredAction`, when present.
2. Vendor-advisory / patch / mitigation references carried by the NVD CVE record.
3. NVD CPE version boundaries as a version-range hint.
4. Generic vendor-supported patch/upgrade/removal guidance when no stronger source is available.

A version boundary from NVD is not automatically presented as a universal fixed build. Branch-specific vendor guidance remains authoritative.

## Closure validation
After remediation, verify installed product/version/configuration, re-run the scanner/applicability check, confirm intended exposure reduction, and retain evidence for closure.

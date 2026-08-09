from __future__ import annotations

import json
from typing import Any

import pandas as pd

from .utils import as_bool


def _load_matches(value: Any) -> list[dict]:
    if isinstance(value, list):
        return value
    if not value or (isinstance(value, float) and pd.isna(value)):
        return []
    try:
        parsed = json.loads(str(value))
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return []


def _fixed_boundary_hints(matches: list[dict]) -> tuple[list[str], list[str]]:
    first_not_affected: list[str] = []
    beyond: list[str] = []
    for match in matches:
        value = match.get("version_end_excluding")
        if value and str(value) not in first_not_affected:
            first_not_affected.append(str(value))
        value = match.get("version_end_including")
        if value and str(value) not in beyond:
            beyond.append(str(value))
    return first_not_affected[:6], beyond[:6]


def remediation_guidance(row: pd.Series | dict) -> dict[str, Any]:
    """Generate source-aware remediation guidance.

    The engine intentionally does not scrape arbitrary web pages or invent fixed versions.
    CISA required actions, NVD CPE boundaries, and vendor/patch references are used when present.
    """
    status = str(row.get("applicability_status") or "UNKNOWN")
    vuln_status = str(row.get("vuln_status") or "").lower()
    kev_action = str(row.get("kev_required_action") or "").strip()
    vendor_urls = str(row.get("vendor_advisory_urls") or "").strip()
    patch_urls = str(row.get("patch_reference_urls") or "").strip()
    mitigation_urls = str(row.get("mitigation_reference_urls") or "").strip()
    advisory_urls = str(row.get("advisory_urls") or "").strip()
    matches = _load_matches(row.get("cpe_matches_json"))
    fixed_candidates, beyond_candidates = _fixed_boundary_hints(matches)

    if "reject" in vuln_status:
        return {
            "remediation_primary": "NVD marks this CVE as rejected. Validate the record/status before taking CVE-specific remediation action.",
            "remediation_secondary": "Continue normal vendor-supported patching and investigate only if another authoritative source identifies a valid issue.",
            "fixed_version_hint": "",
            "remediation_confidence": "HIGH",
            "remediation_source": "NVD CVE status",
            "remediation_validation": "Document why the finding was closed and retain the source/status evidence.",
        }

    if status == "OUT_OF_RANGE":
        return {
            "remediation_primary": "Do not patch solely because the CVE was entered. Verify the installed version against the vendor advisory; if the version is confirmed outside the affected range, close as not applicable.",
            "remediation_secondary": "Keep the product on a vendor-supported release and retain applicability evidence (inventory/SBOM/version output).",
            "fixed_version_hint": "",
            "remediation_confidence": "HIGH",
            "remediation_source": "NVD CPE applicability + asset version",
            "remediation_validation": "Re-run version/applicability check and confirm the scanner/finding no longer reports the vulnerable range.",
        }

    if kev_action:
        primary = kev_action
        source = "CISA KEV requiredAction"
        confidence = "HIGH"
    elif fixed_candidates:
        primary = (
            "Upgrade to a vendor-supported fixed release at or above the first non-vulnerable boundary "
            f"shown by NVD ({', '.join(fixed_candidates)}), after confirming the correct branch in the vendor advisory."
        )
        source = "NVD CPE version range"
        confidence = "MEDIUM-HIGH" if vendor_urls or patch_urls else "MEDIUM"
    elif beyond_candidates:
        primary = (
            "Upgrade beyond the NVD-listed affected upper bound(s) "
            f"({', '.join(beyond_candidates)}) using the vendor-supported fixed release for your branch."
        )
        source = "NVD CPE version range"
        confidence = "MEDIUM"
    else:
        primary = "Apply the vendor security update or supported mitigation for this CVE. If no supported mitigation exists, upgrade or remove the affected component according to vendor guidance."
        source = "NVD/CISA/vendor-reference context"
        confidence = "MEDIUM" if (vendor_urls or patch_urls or advisory_urls) else "LOW"

    secondary_parts: list[str] = []
    if status in {"UNKNOWN", "POSSIBLE", "UNVERIFIED"}:
        secondary_parts.append("Confirm product/version applicability before scheduling disruptive remediation.")
    if mitigation_urls:
        secondary_parts.append("A mitigation/workaround reference is present; use it only as documented by the vendor when immediate patching is not feasible.")
    elif vendor_urls or advisory_urls:
        secondary_parts.append("Review the vendor advisory for branch-specific fixed versions, prerequisites, reboot requirements, and temporary mitigations.")
    if as_bool(row.get("known_exploited")):
        secondary_parts.append("Because the CVE is in CISA KEV, prioritize exposure reduction and validation even when a full patch must wait for a change window.")

    fixed_hint = ""
    if fixed_candidates:
        fixed_hint = "Potential first non-vulnerable boundary from NVD: " + ", ".join(fixed_candidates)
    elif beyond_candidates:
        fixed_hint = "NVD shows affected through: " + ", ".join(beyond_candidates) + "; use a later vendor-supported release."

    return {
        "remediation_primary": primary,
        "remediation_secondary": " ".join(secondary_parts) or "Validate the remediation in a representative environment and follow the vendor-supported change procedure.",
        "fixed_version_hint": fixed_hint,
        "remediation_confidence": confidence,
        "remediation_source": source,
        "remediation_validation": (
            "After remediation: verify the installed version/configuration, rescan or re-run the applicability check, "
            "confirm exposed services are reduced as intended, and retain evidence for closure."
        ),
    }

from __future__ import annotations

import json
import re
from typing import Any

import pandas as pd


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


def _terms(row: pd.Series | dict) -> list[str]:
    values: list[str] = []
    for match in _load_matches(row.get("cpe_matches_json")):
        vendor = str(match.get("vendor") or "").replace("_", " ").strip()
        product = str(match.get("product") or "").replace("_", " ").strip()
        label = " ".join(x for x in [vendor, product] if x).strip()
        if label and label not in values:
            values.append(label)
    for value in [row.get("asset_product"), row.get("product"), row.get("kev_product")]:
        text = str(value or "").replace("_", " ").strip()
        if text and text not in values:
            values.append(text)
    return values[:8]


def _search_regex(terms: list[str]) -> str:
    tokens: list[str] = []
    for term in terms:
        for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9+._-]{2,}", term):
            token = token.replace(".", r"\.")
            if token.lower() not in {"inc", "corp", "foundation", "software"} and token not in tokens:
                tokens.append(token)
    return "|".join(tokens[:4]) or "<product-name>"


def detection_guidance(row: pd.Series | dict) -> dict[str, Any]:
    """Create conservative inventory/detection guidance without inventing file paths."""
    matches = _load_matches(row.get("cpe_matches_json"))
    terms = _terms(row)
    regex = _search_regex(terms)
    parts = {str(m.get("part") or "") for m in matches}
    os_family = str(row.get("os_family") or "").strip().lower()

    if "h" in parts:
        component_type = "Hardware / firmware"
        where = "Check hardware inventory, firmware/BMC/network-appliance inventory, and vendor management consoles for the affected model/firmware."
    elif "o" in parts:
        component_type = "Operating system / platform"
        where = "Check operating-system inventory, image baselines, VM/container base images, and patch-management inventory for the affected OS/build."
    else:
        component_type = "Application / library / service"
        where = "Check software inventory, SBOM/dependency inventory, installed packages, running services, container images, and application manifests for the affected component."

    commands: list[str] = []
    if os_family in {"linux", "rhel", "redhat", "ubuntu", "debian", "centos", "fedora", "suse"}:
        commands = [
            f"rpm -qa | grep -Ei '{regex}'  # RPM-based systems",
            f"dpkg-query -W | grep -Ei '{regex}'  # Debian/Ubuntu",
            f"systemctl --type=service --all | grep -Ei '{regex}'  # service names",
        ]
    elif os_family in {"windows", "win", "windows server"}:
        commands = [
            f"Get-Package | Where-Object {{$_.Name -match '{regex}'}}",
            f"Get-Service | Where-Object {{$_.Name -match '{regex}' -or $_.DisplayName -match '{regex}'}}",
        ]
    elif os_family in {"macos", "mac", "darwin"}:
        commands = [
            f"brew list --versions | grep -Ei '{regex}'  # if Homebrew is used",
            f"pkgutil --pkgs | grep -Ei '{regex}'",
        ]
    else:
        commands = [
            "Use your CMDB/software inventory or SBOM to search the affected vendor/product names and compare installed versions with the listed vulnerable ranges.",
            "For containers, check the image SBOM/package inventory as well as the host; for appliances, check the vendor model and firmware inventory.",
        ]

    return {
        "component_type": component_type,
        "inventory_search_terms": ", ".join(terms) if terms else "Not identified by NVD",
        "where_to_look": where,
        "verification_commands": "\n".join(commands),
        "detection_note": (
            "RiskBridge does not claim a filesystem path unless an authoritative source provides one. "
            "Verify product and version using inventory/SBOM/vendor tooling; a filename alone is not proof of applicability."
        ),
    }

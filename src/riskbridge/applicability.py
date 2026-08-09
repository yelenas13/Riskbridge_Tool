from __future__ import annotations

import json
import re
from typing import Any

import pandas as pd
from packaging.version import InvalidVersion, Version


def _norm(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = text.replace("\\", "")
    return re.sub(r"[^a-z0-9]+", "", text)


def _asset_identity(row: pd.Series | dict) -> tuple[str, str, str]:
    vendor = str(row.get("asset_vendor") or row.get("vendor") or "").strip()
    product = str(row.get("asset_product") or row.get("software_product") or "").strip()
    version = str(
        row.get("asset_version")
        or row.get("installed_version")
        or row.get("software_version")
        or ""
    ).strip()

    finding_product = str(row.get("product") or "").strip()
    if not product and finding_product:
        if ":" in finding_product:
            maybe_vendor, maybe_product = finding_product.split(":", 1)
            vendor = vendor or maybe_vendor.strip()
            product = maybe_product.strip()
        else:
            product = finding_product
    return vendor, product, version


def _safe_version(value: str):
    value = str(value or "").strip()
    if not value or value in {"*", "-"}:
        return None
    try:
        return Version(value)
    except InvalidVersion:
        # Conservative fallback for common vendor versions such as 1.2.3p1.
        tokens = re.findall(r"\d+|[a-zA-Z]+", value.lower())
        return tuple(int(t) if t.isdigit() else t for t in tokens)


def _compare(a: str, b: str) -> int | None:
    va = _safe_version(a)
    vb = _safe_version(b)
    if va is None or vb is None:
        return None
    try:
        return (va > vb) - (va < vb)
    except TypeError:
        # Mixed fallback token types may not be directly comparable.
        return None


def _version_in_match(version: str, match: dict) -> bool | None:
    """Return True/False when NVD range data is sufficient, else None."""
    if not version:
        return None

    exact = str(match.get("version") or "").strip()
    if exact not in {"", "*", "-"}:
        cmp_exact = _compare(version, exact)
        return None if cmp_exact is None else cmp_exact == 0

    checks: list[bool] = []
    for key, op in (
        ("version_start_including", ">="),
        ("version_start_excluding", ">"),
        ("version_end_including", "<="),
        ("version_end_excluding", "<"),
    ):
        bound = match.get(key)
        if not bound:
            continue
        cmp_value = _compare(version, str(bound))
        if cmp_value is None:
            return None
        checks.append(
            (cmp_value >= 0 if op == ">=" else
             cmp_value > 0 if op == ">" else
             cmp_value <= 0 if op == "<=" else
             cmp_value < 0)
        )

    # A wildcard CPE with no explicit bounds means all versions represented by that match.
    return all(checks) if checks else True


def _load_matches(value: Any) -> list[dict]:
    if isinstance(value, list):
        return [x for x in value if isinstance(x, dict)]
    if not value or (isinstance(value, float) and pd.isna(value)):
        return []
    try:
        parsed = json.loads(str(value))
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return []


def assess_applicability(row: pd.Series | dict) -> dict[str, Any]:
    """Conservatively compare asset software metadata with NVD CPE applicability.

    A product mismatch is never treated as proof that a CVE is safe because inventories and
    NVD applicability data can both be incomplete. Only a matching product with an explicit
    version outside all known affected ranges is marked OUT_OF_RANGE.
    """
    vendor, product, version = _asset_identity(row)
    matches = _load_matches(row.get("cpe_matches_json"))

    if not matches:
        return {
            "applicability_status": "UNKNOWN",
            "applicability_confidence": 20.0,
            "applicability_reason": "NVD CPE applicability data is unavailable; risk is conditional on the CVE applying to this asset.",
            "applicability_assumes_affected": True,
            "asset_vendor_resolved": vendor,
            "asset_product_resolved": product,
            "asset_version_resolved": version,
        }

    if not product:
        return {
            "applicability_status": "UNKNOWN",
            "applicability_confidence": 30.0,
            "applicability_reason": "Asset product/version were not provided. Add product and installed version to verify applicability.",
            "applicability_assumes_affected": True,
            "asset_vendor_resolved": vendor,
            "asset_product_resolved": product,
            "asset_version_resolved": version,
        }

    product_n = _norm(product)
    vendor_n = _norm(vendor)
    product_matches: list[dict] = []
    for match in matches:
        mp = _norm(match.get("product"))
        mv = _norm(match.get("vendor"))
        product_ok = bool(product_n and mp and (product_n == mp or product_n in mp or mp in product_n))
        vendor_ok = not vendor_n or not mv or vendor_n == mv or vendor_n in mv or mv in vendor_n
        if product_ok and vendor_ok:
            product_matches.append(match)

    if not product_matches:
        affected_names = sorted({f"{m.get('vendor','')}:{m.get('product','')}" for m in matches})[:6]
        return {
            "applicability_status": "UNVERIFIED",
            "applicability_confidence": 25.0,
            "applicability_reason": (
                f"Asset product '{product}' did not match NVD CPE names ({', '.join(affected_names) or 'not listed'}). "
                "This is not proof of non-applicability; verify inventory/SBOM and vendor advisory."
            ),
            "applicability_assumes_affected": True,
            "asset_vendor_resolved": vendor,
            "asset_product_resolved": product,
            "asset_version_resolved": version,
        }

    if not version:
        return {
            "applicability_status": "POSSIBLE",
            "applicability_confidence": 60.0,
            "applicability_reason": "Product matches NVD applicability, but installed version is missing; verify the installed version.",
            "applicability_assumes_affected": True,
            "asset_vendor_resolved": vendor,
            "asset_product_resolved": product,
            "asset_version_resolved": version,
        }

    evaluations = [_version_in_match(version, match) for match in product_matches]
    if any(result is True for result in evaluations):
        return {
            "applicability_status": "CONFIRMED",
            "applicability_confidence": 100.0,
            "applicability_reason": f"Asset product/version {product} {version} matches an NVD vulnerable CPE/range.",
            "applicability_assumes_affected": False,
            "asset_vendor_resolved": vendor,
            "asset_product_resolved": product,
            "asset_version_resolved": version,
        }

    if evaluations and all(result is False for result in evaluations):
        return {
            "applicability_status": "OUT_OF_RANGE",
            "applicability_confidence": 95.0,
            "applicability_reason": f"Asset product matches NVD, but installed version {version} is outside the listed vulnerable range(s). Verify against the vendor advisory before closure.",
            "applicability_assumes_affected": False,
            "asset_vendor_resolved": vendor,
            "asset_product_resolved": product,
            "asset_version_resolved": version,
        }

    return {
        "applicability_status": "POSSIBLE",
        "applicability_confidence": 55.0,
        "applicability_reason": "Product matches, but the installed version could not be reliably compared with NVD version syntax. Verify with the vendor advisory or SBOM tooling.",
        "applicability_assumes_affected": True,
        "asset_vendor_resolved": vendor,
        "asset_product_resolved": product,
        "asset_version_resolved": version,
    }

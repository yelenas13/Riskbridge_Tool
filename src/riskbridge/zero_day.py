from __future__ import annotations

from typing import Any
import pandas as pd

from .utils import as_bool, as_float, clamp, normalize_1_to_5, weighted_average
from .scoring import business_score, control_effectiveness_score


def _attack_surface(row: pd.Series | dict) -> float | None:
    ports = as_float(row.get("open_ports"))
    port_score = clamp((ports or 0) / 20 * 100) if ports is not None else None
    return weighted_average(
        {
            "internet": 100.0 if as_bool(row.get("internet_exposed")) else 0.0,
            "public_api": 100.0 if as_bool(row.get("public_api")) else 0.0,
            "remote_access": 100.0 if as_bool(row.get("remote_access")) else 0.0,
            "ports": port_score,
            "third_party": 100.0 if as_bool(row.get("third_party_exposure")) else 0.0,
        },
        {"internet": 0.35, "public_api": 0.20, "remote_access": 0.20, "ports": 0.10, "third_party": 0.15},
    )


def _privilege_reachability(row: pd.Series | dict) -> float | None:
    return weighted_average(
        {
            "privilege": 100.0 if as_bool(row.get("privileged")) else 0.0,
            "reach": normalize_1_to_5(row.get("network_reachability")),
            "identity": normalize_1_to_5(row.get("identity_criticality")),
        },
        {"privilege": 0.35, "reach": 0.40, "identity": 0.25},
    )


def _software_exposure(row: pd.Series | dict) -> float | None:
    age = as_float(row.get("technology_age_years"))
    age_score = clamp((age or 0.0) / 10.0 * 100.0) if age is not None else None
    return weighted_average(
        {
            "unsupported": 100.0 if as_bool(row.get("unsupported_software")) else 0.0,
            "age": age_score,
            "third_party": 100.0 if as_bool(row.get("third_party_exposure")) else 0.0,
        },
        {"unsupported": 0.45, "age": 0.30, "third_party": 0.25},
    )


def zero_day_preparedness(row: pd.Series | dict) -> dict[str, Any]:
    """Preparedness is separate from exposure: can the organization contain/recover quickly?"""
    dimensions = {
        "Isolation readiness": normalize_1_to_5(row.get("isolation_readiness")),
        "Emergency patching": normalize_1_to_5(row.get("emergency_patching_readiness")),
        "Recovery readiness": normalize_1_to_5(row.get("recovery_readiness")),
        "Inventory accuracy": normalize_1_to_5(row.get("inventory_accuracy")),
        "Telemetry readiness": normalize_1_to_5(row.get("telemetry_readiness")),
        "Change flexibility": normalize_1_to_5(row.get("change_flexibility")),
    }
    weights = {name: 1 / len(dimensions) for name in dimensions}
    score = weighted_average(dimensions, weights)
    if score is None:
        return {
            "zero_day_preparedness_score": None,
            "zero_day_preparedness_rating": "UNAVAILABLE",
            "zero_day_preparedness_drivers": "Preparedness inputs not supplied",
        }
    score = round(clamp(score), 2)
    if score >= 80:
        rating = "STRONG"
    elif score >= 60:
        rating = "MODERATE"
    elif score >= 40:
        rating = "LIMITED"
    else:
        rating = "WEAK"
    weakest = sorted(
        [(name, value) for name, value in dimensions.items() if value is not None],
        key=lambda pair: pair[1],
    )[:3]
    return {
        "zero_day_preparedness_score": score,
        "zero_day_preparedness_rating": rating,
        "zero_day_preparedness_drivers": "; ".join(f"{name} {value:.0f}/100" for name, value in weakest),
    }


def zero_day_exposure(row: pd.Series | dict, config: dict) -> dict[str, Any]:
    """Pre-CVE exposure model. No CVSS, EPSS, KEV, or CVE is required."""
    attack = _attack_surface(row)
    privilege = _privilege_reachability(row)
    software = _software_exposure(row)
    business = business_score(row)
    controls = control_effectiveness_score(row)
    weakness = 100.0 - controls if controls is not None else None

    weights = config.get("zero_day", {}).get(
        "weights",
        {
            "attack_surface": 0.25,
            "privilege_reachability": 0.20,
            "software_exposure": 0.20,
            "business_impact": 0.25,
            "control_weakness": 0.10,
        },
    )
    score = weighted_average(
        {
            "attack_surface": attack,
            "privilege_reachability": privilege,
            "software_exposure": software,
            "business_impact": business,
            "control_weakness": weakness,
        },
        weights,
    )
    score = round(clamp(score or 0.0), 2)
    if score >= 85:
        rating = "CRITICAL"
    elif score >= 70:
        rating = "HIGH"
    elif score >= 50:
        rating = "MEDIUM"
    else:
        rating = "LOW"

    dimensions = {
        "Attack Surface": attack,
        "Privilege & Reachability": privilege,
        "Software Exposure": software,
        "Business Impact": business,
        "Control Weakness": weakness,
    }
    drivers = sorted(
        [(name, value) for name, value in dimensions.items() if value is not None],
        key=lambda pair: pair[1],
        reverse=True,
    )[:3]
    explanation = "; ".join(f"{name} {value:.0f}/100" for name, value in drivers)
    preparedness = zero_day_preparedness(row)
    prep_score = preparedness.get("zero_day_preparedness_score")
    response_gap = round(max(0.0, score - float(prep_score)), 2) if prep_score is not None else None

    return {
        "zd_attack_surface": round(attack, 2) if attack is not None else None,
        "zd_privilege_reachability": round(privilege, 2) if privilege is not None else None,
        "zd_software_exposure": round(software, 2) if software is not None else None,
        "zd_business_impact": round(business, 2) if business is not None else None,
        "zd_control_weakness": round(weakness, 2) if weakness is not None else None,
        "zero_day_exposure_score": score,
        "zero_day_exposure_rating": rating,
        "zero_day_drivers": explanation,
        **preparedness,
        "zero_day_response_gap": response_gap,
    }

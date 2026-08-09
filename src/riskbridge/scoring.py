from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
import math

import pandas as pd

from .utils import as_bool, as_float, clamp, normalize_1_to_5, weighted_average

DEFAULT_WEIGHTS = {
    "technical": 0.20,
    "threat": 0.30,
    "business": 0.30,
    "exposure": 0.20,
}


def technical_score(row: pd.Series | dict) -> float | None:
    score = as_float(row.get("cvss_score"))
    return clamp(score * 10.0) if score is not None else None


def threat_score(row: pd.Series | dict) -> float | None:
    epss = as_float(row.get("epss"))
    percentile = as_float(row.get("epss_percentile"))
    known_exploited_raw = row.get("known_exploited")
    kev_available = known_exploited_raw is not None and not pd.isna(known_exploited_raw)

    signals: dict[str, float | None] = {
        "epss": clamp(epss * 100.0) if epss is not None else None,
        "percentile": clamp(percentile * 100.0) if percentile is not None else None,
        "kev": 100.0 if kev_available and as_bool(known_exploited_raw) else (0.0 if kev_available else None),
    }
    weights = {"epss": 0.50, "percentile": 0.20, "kev": 0.30}
    return weighted_average(signals, weights)


def business_score(row: pd.Series | dict) -> float | None:
    env = str(row.get("environment", "")).strip().lower()
    env_score = {"production": 100.0, "prod": 100.0, "preprod": 70.0, "staging": 60.0,
                 "test": 35.0, "development": 25.0, "dev": 25.0}.get(env)
    values = {
        "criticality": normalize_1_to_5(row.get("criticality")),
        "data": normalize_1_to_5(row.get("data_sensitivity")),
        "revenue": normalize_1_to_5(row.get("revenue_impact")),
        "safety": normalize_1_to_5(row.get("safety_impact")),
        "environment": env_score,
    }
    weights = {"criticality": 0.35, "data": 0.20, "revenue": 0.15, "safety": 0.15, "environment": 0.15}
    return weighted_average(values, weights)


def exposure_score(row: pd.Series | dict) -> float | None:
    reach = normalize_1_to_5(row.get("network_reachability"))
    open_ports = as_float(row.get("open_ports"))
    open_port_score = clamp((open_ports or 0.0) / 20.0 * 100.0) if open_ports is not None else None
    values = {
        "internet": 100.0 if as_bool(row.get("internet_exposed")) else 0.0,
        "privileged": 100.0 if as_bool(row.get("privileged")) else 0.0,
        "public_api": 100.0 if as_bool(row.get("public_api")) else 0.0,
        "remote_access": 100.0 if as_bool(row.get("remote_access")) else 0.0,
        "reachability": reach,
        "open_ports": open_port_score,
    }
    weights = {
        "internet": 0.30,
        "privileged": 0.15,
        "public_api": 0.10,
        "remote_access": 0.10,
        "reachability": 0.25,
        "open_ports": 0.10,
    }
    return weighted_average(values, weights)


def control_effectiveness_score(row: pd.Series | dict) -> float | None:
    values = {
        "segmentation": normalize_1_to_5(row.get("segmentation_effectiveness")),
        "edr": normalize_1_to_5(row.get("edr_effectiveness")),
        "waf": normalize_1_to_5(row.get("waf_effectiveness")),
        "least_privilege": normalize_1_to_5(row.get("least_privilege_effectiveness")),
        "monitoring": normalize_1_to_5(row.get("monitoring_effectiveness")),
    }
    weights = {key: 0.20 for key in values}
    return weighted_average(values, weights)


def emerging_vulnerability_score(row: pd.Series | dict) -> float | None:
    """Post-disclosure emerging-risk score. This is deliberately NOT called a zero-day score."""
    epss = as_float(row.get("epss"))
    percentile = as_float(row.get("epss_percentile"))
    cvss = as_float(row.get("cvss_score"))
    published = row.get("published")
    recency: float | None = None
    if published:
        try:
            dt = datetime.fromisoformat(str(published).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            days = max(0, (datetime.now(timezone.utc) - dt).days)
            recency = clamp(100.0 / (1.0 + days / 14.0))
        except Exception:
            recency = None
    values = {
        "epss": epss * 100.0 if epss is not None else None,
        "percentile": percentile * 100.0 if percentile is not None else None,
        "technical": cvss * 10.0 if cvss is not None else None,
        "recency": recency,
    }
    weights = {"epss": 0.40, "percentile": 0.20, "technical": 0.20, "recency": 0.20}
    value = weighted_average(values, weights)
    return clamp(value) if value is not None else None


def data_confidence(row: pd.Series | dict) -> tuple[float, str]:
    checks = {
        "CVSS": row.get("cvss_score") is not None and not pd.isna(row.get("cvss_score")),
        "EPSS": row.get("epss") is not None and not pd.isna(row.get("epss")),
        "KEV": row.get("known_exploited") is not None and not pd.isna(row.get("known_exploited")),
        "asset criticality": row.get("criticality") is not None and not pd.isna(row.get("criticality")),
        "exposure": row.get("network_reachability") is not None and not pd.isna(row.get("network_reachability")),
        "controls": any(row.get(k) is not None and not pd.isna(row.get(k)) for k in (
            "segmentation_effectiveness", "edr_effectiveness", "waf_effectiveness",
            "least_privilege_effectiveness", "monitoring_effectiveness"
        )),
    }
    present = sum(1 for ok in checks.values() if ok)
    confidence = present / len(checks) * 100.0
    gaps = ", ".join(name for name, ok in checks.items() if not ok)
    return round(confidence, 1), gaps


def priority_for(score: float, row: pd.Series | dict, business: float | None, exposure: float | None) -> str:
    priority = "P3"
    if score >= 85:
        priority = "P0"
    elif score >= 70:
        priority = "P1"
    elif score >= 50:
        priority = "P2"

    kev = as_bool(row.get("known_exploited"))
    epss = as_float(row.get("epss"), 0.0) or 0.0
    if kev and ((business or 0) >= 75 or (exposure or 0) >= 70):
        return "P0"
    if kev and priority in {"P2", "P3"}:
        return "P1"
    if epss >= 0.90 and (business or 0) >= 75 and (exposure or 0) >= 60:
        return "P0"
    return priority


def score_finding(row: pd.Series | dict, config: dict) -> dict[str, Any]:
    tech = technical_score(row)
    threat = threat_score(row)
    business = business_score(row)
    exposure = exposure_score(row)
    controls = control_effectiveness_score(row)

    weights = config.get("scoring", {}).get("weights", DEFAULT_WEIGHTS)
    base = weighted_average(
        {"technical": tech, "threat": threat, "business": business, "exposure": exposure},
        weights,
    )
    base = base if base is not None else 0.0

    cap = float(config.get("scoring", {}).get("control_mitigation_cap", 0.35))
    residual = base * (1.0 - ((controls or 0.0) / 100.0) * cap)
    residual = round(clamp(residual), 2)
    priority = priority_for(residual, row, business, exposure)
    confidence, gaps = data_confidence(row)
    emerging = emerging_vulnerability_score(row)

    driver_map = {
        "Technical severity": tech,
        "Threat likelihood": threat,
        "Business impact": business,
        "Exposure": exposure,
        "Control weakness": (100.0 - controls) if controls is not None else None,
    }
    drivers = sorted(
        [(name, value) for name, value in driver_map.items() if value is not None],
        key=lambda pair: pair[1],
        reverse=True,
    )[:3]
    why = "; ".join(f"{name} {value:.0f}/100" for name, value in drivers)

    return {
        "technical_score": round(tech, 2) if tech is not None else None,
        "threat_score": round(threat, 2) if threat is not None else None,
        "business_score": round(business, 2) if business is not None else None,
        "exposure_score": round(exposure, 2) if exposure is not None else None,
        "control_effectiveness": round(controls, 2) if controls is not None else None,
        "riskbridge_score": residual,
        "priority": priority,
        "emerging_vulnerability_score": round(emerging, 2) if emerging is not None else None,
        "confidence": confidence,
        "data_gaps": gaps,
        "top_risk_drivers": why,
    }

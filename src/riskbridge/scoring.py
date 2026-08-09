from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pandas as pd

from .utils import as_bool, as_float, clamp, normalize_1_to_5, weighted_average

DEFAULT_WEIGHTS = {
    "technical": 0.20,
    "threat": 0.30,
    "business": 0.30,
    "exposure": 0.20,
}
DEFAULT_THREAT_WEIGHTS = {
    "epss": 0.35,
    "percentile": 0.15,
    "kev": 0.25,
    "velocity": 0.10,
    "ml": 0.15,
}


def technical_score(row: pd.Series | dict) -> float | None:
    score = as_float(row.get("cvss_score"))
    return clamp(score * 10.0) if score is not None else None


def threat_score(row: pd.Series | dict, config: dict | None = None) -> float | None:
    epss = as_float(row.get("epss"))
    percentile = as_float(row.get("epss_percentile"))
    velocity = as_float(row.get("epss_velocity_score"))
    ml_probability = as_float(row.get("ml_exploitation_probability"))
    known_exploited_raw = row.get("known_exploited")
    kev_available = known_exploited_raw is not None and not pd.isna(known_exploited_raw)

    signals: dict[str, float | None] = {
        "epss": clamp(epss * 100.0) if epss is not None else None,
        "percentile": clamp(percentile * 100.0) if percentile is not None else None,
        "kev": 100.0 if kev_available and as_bool(known_exploited_raw) else (0.0 if kev_available else None),
        "velocity": clamp(velocity) if velocity is not None else None,
        "ml": clamp(ml_probability * 100.0) if ml_probability is not None else None,
    }
    weights = (config or {}).get("scoring", {}).get("threat_weights", DEFAULT_THREAT_WEIGHTS)
    return weighted_average(signals, weights)


def business_score(row: pd.Series | dict) -> float | None:
    env = str(row.get("environment", "")).strip().lower()
    env_score = {
        "production": 100.0,
        "prod": 100.0,
        "preprod": 70.0,
        "staging": 60.0,
        "test": 35.0,
        "development": 25.0,
        "dev": 25.0,
    }.get(env)
    values = {
        "criticality": normalize_1_to_5(row.get("criticality")),
        "data": normalize_1_to_5(row.get("data_sensitivity")),
        "revenue": normalize_1_to_5(row.get("revenue_impact")),
        "safety": normalize_1_to_5(row.get("safety_impact")),
        "environment": env_score,
    }
    weights = {
        "criticality": 0.35,
        "data": 0.20,
        "revenue": 0.15,
        "safety": 0.15,
        "environment": 0.15,
    }
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
    """Post-disclosure emerging-risk score; not a zero-day prediction."""
    epss = as_float(row.get("epss"))
    percentile = as_float(row.get("epss_percentile"))
    cvss = as_float(row.get("cvss_score"))
    velocity = as_float(row.get("epss_velocity_score"))
    ml_probability = as_float(row.get("ml_exploitation_probability"))
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
        "velocity": velocity,
        "ml": ml_probability * 100.0 if ml_probability is not None else None,
    }
    weights = {
        "epss": 0.30,
        "percentile": 0.15,
        "technical": 0.15,
        "recency": 0.15,
        "velocity": 0.10,
        "ml": 0.15,
    }
    value = weighted_average(values, weights)
    return clamp(value) if value is not None else None


def _freshness_quality(row: pd.Series | dict) -> float:
    checked = row.get("intelligence_checked_at")
    if not checked:
        return 0.5
    try:
        dt = datetime.fromisoformat(str(checked).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        age_hours = max(0.0, (datetime.now(timezone.utc) - dt).total_seconds() / 3600)
        if age_hours <= 48:
            return 1.0
        if age_hours <= 168:
            return 0.8
        if age_hours <= 720:
            return 0.5
        return 0.2
    except Exception:
        return 0.5


def data_confidence(row: pd.Series | dict) -> tuple[float, str]:
    applicability = as_float(row.get("applicability_confidence"), 0.0) or 0.0
    checks: dict[str, tuple[float, float]] = {
        "CVSS": (1.0 if as_float(row.get("cvss_score")) is not None else 0.0, 15),
        "EPSS": (1.0 if as_float(row.get("epss")) is not None else 0.0, 10),
        "KEV check": (
            1.0 if row.get("known_exploited") is not None and not pd.isna(row.get("known_exploited")) else 0.0,
            10,
        ),
        "EPSS trend": (1.0 if as_float(row.get("epss_velocity_score")) is not None else 0.5, 5),
        "business context": (
            1.0 if row.get("criticality") is not None and not pd.isna(row.get("criticality")) else 0.0,
            15,
        ),
        "exposure context": (
            1.0 if row.get("network_reachability") is not None and not pd.isna(row.get("network_reachability")) else 0.0,
            10,
        ),
        "controls": (
            1.0 if any(
                row.get(k) is not None and not pd.isna(row.get(k))
                for k in (
                    "segmentation_effectiveness",
                    "edr_effectiveness",
                    "waf_effectiveness",
                    "least_privilege_effectiveness",
                    "monitoring_effectiveness",
                )
            ) else 0.0,
            10,
        ),
        "applicability": (clamp(applicability) / 100.0, 15),
        "remediation evidence": (
            1.0 if any(str(row.get(k) or "").strip() for k in ("kev_required_action", "vendor_advisory_urls", "patch_reference_urls")) else 0.4,
            5,
        ),
        "source freshness": (_freshness_quality(row), 5),
    }
    total_weight = sum(weight for _, weight in checks.values())
    confidence = sum(quality * weight for quality, weight in checks.values()) / total_weight * 100.0
    if str(row.get("intelligence_errors") or "").strip():
        confidence = max(0.0, confidence - 10.0)
    gaps = ", ".join(name for name, (quality, _) in checks.items() if quality < 0.75)
    return round(confidence, 1), gaps


def priority_for(score: float, row: pd.Series | dict, business: float | None, exposure: float | None) -> str:
    if str(row.get("applicability_status") or "") == "OUT_OF_RANGE":
        return "NA"
    priority = "P3"
    if score >= 85:
        priority = "P0"
    elif score >= 70:
        priority = "P1"
    elif score >= 50:
        priority = "P2"

    kev = as_bool(row.get("known_exploited"))
    epss = as_float(row.get("epss"), 0.0) or 0.0
    ml_probability = as_float(row.get("ml_exploitation_probability"), 0.0) or 0.0
    if kev and ((business or 0) >= 75 or (exposure or 0) >= 70):
        return "P0"
    if kev and priority in {"P2", "P3"}:
        return "P1"
    if epss >= 0.90 and (business or 0) >= 75 and (exposure or 0) >= 60:
        return "P0"
    if ml_probability >= 0.90 and (business or 0) >= 75 and (exposure or 0) >= 60:
        return "P0"
    return priority


def score_finding(row: pd.Series | dict, config: dict) -> dict[str, Any]:
    tech = technical_score(row)
    threat = threat_score(row, config)
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
    conditional_score = residual
    priority = priority_for(residual, row, business, exposure)
    if priority == "NA":
        residual = 0.0

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

    applicability_status = str(row.get("applicability_status") or "UNKNOWN")
    if applicability_status == "OUT_OF_RANGE":
        decision_note = "Not applicable by current NVD product/version comparison; verify vendor advisory before closure."
    elif as_bool(row.get("applicability_assumes_affected")):
        decision_note = "Risk score is conditional and assumes the CVE applies because applicability is not fully confirmed."
    else:
        decision_note = "Applicability is confirmed by available product/version context."

    return {
        "technical_score": round(tech, 2) if tech is not None else None,
        "threat_score": round(threat, 2) if threat is not None else None,
        "business_score": round(business, 2) if business is not None else None,
        "exposure_score": round(exposure, 2) if exposure is not None else None,
        "control_effectiveness": round(controls, 2) if controls is not None else None,
        "inherent_risk_score": round(clamp(base), 2),
        "conditional_riskbridge_score": conditional_score,
        "riskbridge_score": residual,
        "priority": priority,
        "emerging_vulnerability_score": round(emerging, 2) if emerging is not None else None,
        "confidence": confidence,
        "data_gaps": gaps,
        "top_risk_drivers": why,
        "decision_note": decision_note,
    }

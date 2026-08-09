from __future__ import annotations

import pandas as pd

from .scoring import score_finding


def simulate_interventions(row: pd.Series | dict, config: dict) -> pd.DataFrame:
    """What-if analysis using the same transparent RiskBridge scoring engine.

    These are modeled scenarios, not promises that a control will reduce real-world loss by the
    exact number shown. Patch/remediate means the specific known-CVE finding is removed.
    """
    base_row = dict(row)
    baseline = float(score_finding(pd.Series(base_row), config)["riskbridge_score"])
    effort = config.get("simulator", {}).get("effort_hours", {})

    scenarios: list[tuple[str, dict, float, str]] = [
        (
            "Patch / remove vulnerable condition",
            {"__patched__": True},
            float(effort.get("patch", row.get("remediation_hours") or 2.0)),
            "Assumes the vendor-supported remediation removes this specific CVE finding and is successfully validated.",
        ),
        (
            "Remove direct internet exposure",
            {"internet_exposed": False, "public_api": False},
            float(effort.get("remove_internet_exposure", 2.0)),
            "Models exposure reduction only; it does not fix the underlying vulnerability.",
        ),
        (
            "Strengthen network segmentation",
            {"segmentation_effectiveness": 5, "network_reachability": min(float(base_row.get("network_reachability") or 3), 2)},
            float(effort.get("segmentation", 4.0)),
            "Models strong segmentation and reduced reachability; engineering validation is required.",
        ),
        (
            "Enforce least privilege",
            {"least_privilege_effectiveness": 5, "privileged": False},
            float(effort.get("least_privilege", 3.0)),
            "Models removal of unnecessary privileged execution/access where technically feasible.",
        ),
        (
            "Strengthen endpoint detection",
            {"edr_effectiveness": 5, "monitoring_effectiveness": max(float(base_row.get("monitoring_effectiveness") or 1), 4)},
            float(effort.get("edr", 2.0)),
            "Models stronger detection/response; it does not eliminate exploitability.",
        ),
        (
            "Strengthen application protection",
            {"waf_effectiveness": 5},
            float(effort.get("waf", 2.0)),
            "Relevant mainly for web/API attack paths; validate that the control can actually observe/block the vulnerable path.",
        ),
    ]

    rows: list[dict] = []
    for action, changes, hours, assumption in scenarios:
        if changes.pop("__patched__", False):
            resulting = 0.0 if str(base_row.get("applicability_status") or "") != "OUT_OF_RANGE" else baseline
        else:
            changed = dict(base_row)
            changed.update(changes)
            resulting = float(score_finding(pd.Series(changed), config)["riskbridge_score"])
        reduction = max(0.0, baseline - resulting)
        rows.append(
            {
                "action": action,
                "baseline_risk": round(baseline, 2),
                "resulting_risk": round(resulting, 2),
                "risk_reduction": round(reduction, 2),
                "estimated_hours": round(max(0.1, hours), 2),
                "risk_reduction_per_hour": round(reduction / max(0.1, hours), 2),
                "assumption": assumption,
            }
        )
    return pd.DataFrame(rows).sort_values("risk_reduction_per_hour", ascending=False).reset_index(drop=True)

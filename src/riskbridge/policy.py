from __future__ import annotations

from datetime import date, timedelta
from typing import Any


def apply_policy(scored_row: dict[str, Any], config: dict) -> dict[str, Any]:
    priority = scored_row.get("priority", "P3")
    sla_days = config.get("organization", {}).get("sla_days", {})
    days = sla_days.get(priority)
    due = (date.today() + timedelta(days=int(days))).isoformat() if days is not None else ""

    mappings = config.get("framework_mappings", {})
    mapped = []
    for framework, controls in mappings.items():
        mapped.append(f"{framework}: {', '.join(str(x) for x in controls)}")

    return {
        "sla_days": days,
        "patch_by": due,
        "framework_mappings": " | ".join(mapped),
        "policy_note": "Remediation SLA is organization-defined; framework mappings are context, not universal SLA claims.",
    }

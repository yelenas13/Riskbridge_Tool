from __future__ import annotations

from datetime import date, timedelta
from typing import Any


def apply_policy(scored_row: dict[str, Any], config: dict) -> dict[str, Any]:
    priority = scored_row.get("priority", "P3")
    if priority == "NA":
        days = None
        due = ""
    else:
        sla_days = config.get("organization", {}).get("sla_days", {})
        days = sla_days.get(priority)
        due = (date.today() + timedelta(days=int(days))).isoformat() if days is not None else ""

    mappings = config.get("framework_mappings", {})
    mapped = [f"{framework}: {', '.join(str(x) for x in controls)}" for framework, controls in mappings.items()]

    exception_active = bool(scored_row.get("exception_active"))
    accept_until = str(scored_row.get("accept_until") or "")
    governance_due = accept_until if exception_active and accept_until else due

    return {
        "sla_days": days,
        "patch_by": due,
        "governance_due_date": governance_due,
        "framework_mappings": " | ".join(mapped),
        "policy_note": (
            "Remediation SLA is organization-defined; framework mappings are context, not universal SLA claims. "
            "An approved exception changes governance timing, not the calculated risk score."
        ),
    }

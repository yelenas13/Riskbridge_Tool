from __future__ import annotations

from datetime import date
from typing import Any

import pandas as pd


def evaluate_exception(row: pd.Series | dict) -> dict[str, Any]:
    """Governance disposition only; acceptance never reduces the calculated risk score."""
    response = str(row.get("risk_response") or row.get("disposition") or "MITIGATE").strip().upper()
    accept_until = pd.to_datetime(row.get("accept_until"), errors="coerce")
    today = pd.Timestamp(date.today())
    active = response in {"ACCEPT", "ACCEPTED", "EXCEPTION"} and pd.notna(accept_until) and accept_until.normalize() >= today
    expired = response in {"ACCEPT", "ACCEPTED", "EXCEPTION"} and pd.notna(accept_until) and accept_until.normalize() < today
    return {
        "risk_response": response,
        "exception_active": bool(active),
        "exception_expired": bool(expired),
        "exception_owner": row.get("exception_owner") or row.get("owner") or "",
        "exception_reason": row.get("exception_reason") or row.get("exception_note") or "",
        "accept_until": accept_until.date().isoformat() if pd.notna(accept_until) else "",
        "governance_note": (
            "Active risk acceptance changes governance status, not residual-risk mathematics."
            if active
            else "Risk is not covered by an active acceptance."
        ),
    }


def exception_record(
    *,
    cve_id: str,
    asset_id: str,
    owner: str,
    reason: str,
    accept_until: str,
    compensating_controls: str = "",
    approver: str = "",
) -> dict[str, str]:
    return {
        "cve_id": cve_id,
        "asset_id": asset_id,
        "risk_response": "ACCEPT",
        "exception_owner": owner,
        "exception_reason": reason,
        "accept_until": accept_until,
        "compensating_controls": compensating_controls,
        "approver": approver,
    }

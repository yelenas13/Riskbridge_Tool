"""Template for future scanner integrations.

The rule is simple: vendor-specific code ends here. Convert scanner exports/API responses
into RiskBridge's normalized finding schema, then pass the normalized DataFrame to the pipeline.

A future Qualys adapter might map Host ID -> asset_id, CVE -> cve_id, QID -> scanner_id,
first-found/last-found/status/port into source fields. Tenable, Defender VM, Rapid7, and other
systems should follow the same pattern.
"""

from __future__ import annotations
import pandas as pd


class VendorConnectorTemplate:
    name = "vendor-template"

    def normalize(self, raw: pd.DataFrame) -> pd.DataFrame:
        raise NotImplementedError("Implement vendor field mapping into the RiskBridge common schema.")

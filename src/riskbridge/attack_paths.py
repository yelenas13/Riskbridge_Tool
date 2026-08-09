from __future__ import annotations

import networkx as nx
import pandas as pd

from .utils import as_bool


def exposure_paths(
    assets: pd.DataFrame,
    relationships: pd.DataFrame,
    scored: pd.DataFrame | None = None,
    zero_day: pd.DataFrame | None = None,
    *,
    cutoff: int = 6,
    max_paths: int = 50,
) -> pd.DataFrame:
    """Structural attack-path-lite analysis.

    Relationships represent declared reachability/dependency, not verified exploitability. The
    output therefore says STRUCTURAL PATH rather than claiming an attacker can definitely traverse it.
    """
    if assets is None or assets.empty or relationships is None or relationships.empty:
        return pd.DataFrame()
    rel = relationships.copy()
    rel.columns = [str(c).strip().lower() for c in rel.columns]
    source_col = "from_asset" if "from_asset" in rel.columns else "source_asset" if "source_asset" in rel.columns else None
    target_col = "to_asset" if "to_asset" in rel.columns else "target_asset" if "target_asset" in rel.columns else None
    if not source_col or not target_col:
        raise ValueError("Relationships CSV requires from_asset,to_asset (or source_asset,target_asset).")

    graph = nx.DiGraph()
    for _, row in rel.iterrows():
        src, dst = str(row[source_col]), str(row[target_col])
        if src and dst:
            graph.add_edge(src, dst, relationship=row.get("relationship", "reachability"))

    asset_index = assets.set_index("asset_id", drop=False)
    entries = [str(r["asset_id"]) for _, r in assets.iterrows() if as_bool(r.get("internet_exposed"))]
    targets = [
        str(r["asset_id"])
        for _, r in assets.iterrows()
        if float(r.get("criticality") or 0) >= 5
        or float(r.get("identity_criticality") or 0) >= 5
        or as_bool(r.get("crown_jewel"))
    ]

    known_by_asset = {}
    if scored is not None and not scored.empty:
        known_by_asset = scored.groupby("asset_id")["riskbridge_score"].max().to_dict()
    zd_by_asset = {}
    if zero_day is not None and not zero_day.empty:
        zd_by_asset = zero_day.groupby("asset_id")["zero_day_exposure_score"].max().to_dict()

    rows: list[dict] = []
    for entry in entries:
        for target in targets:
            if entry == target or entry not in graph or target not in graph:
                continue
            try:
                for path in nx.all_simple_paths(graph, entry, target, cutoff=cutoff):
                    known = max((float(known_by_asset.get(node, 0)) for node in path), default=0.0)
                    zd = max((float(zd_by_asset.get(node, 0)) for node in path), default=0.0)
                    score = round(known * 0.60 + zd * 0.40, 2)
                    rows.append(
                        {
                            "entry_asset": entry,
                            "target_asset": target,
                            "entry_hostname": asset_index.loc[entry].get("hostname", entry) if entry in asset_index.index else entry,
                            "target_hostname": asset_index.loc[target].get("hostname", target) if target in asset_index.index else target,
                            "hops": len(path) - 1,
                            "path": " → ".join(path),
                            "max_known_risk": round(known, 2),
                            "max_zero_day_exposure": round(zd, 2),
                            "structural_path_score": score,
                            "verification": "STRUCTURAL PATH — validate actual network/authentication reachability before treating as an attack path.",
                        }
                    )
                    if len(rows) >= max_paths:
                        return pd.DataFrame(rows).sort_values("structural_path_score", ascending=False).reset_index(drop=True)
            except nx.NetworkXNoPath:
                continue
    return pd.DataFrame(rows).sort_values("structural_path_score", ascending=False).reset_index(drop=True) if rows else pd.DataFrame()

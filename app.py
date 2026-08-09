from __future__ import annotations

from pathlib import Path
import sys

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import yaml

ROOT = Path(__file__).resolve().parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from riskbridge.connectors import load_assets, load_findings
from riskbridge.optimizer import optimize_patch_bundles
from riskbridge.pipeline import run_analysis

st.set_page_config(page_title="RiskBridge", page_icon="🌉", layout="wide")
st.title("RiskBridge")
st.caption("Explainable vulnerability prioritization + pre-CVE zero-day exposure modeling")


def read_uploaded_csv(uploaded, fallback: Path, loader):
    if uploaded is None:
        return loader(fallback)
    tmp = ROOT / ".riskbridge_upload.csv"
    tmp.write_bytes(uploaded.getvalue())
    try:
        return loader(tmp)
    finally:
        tmp.unlink(missing_ok=True)


def load_config(uploaded) -> dict:
    if uploaded is None:
        return yaml.safe_load((ROOT / "config/default.yaml").read_text(encoding="utf-8"))
    return yaml.safe_load(uploaded.getvalue().decode("utf-8")) or {}


with st.sidebar:
    st.header("Inputs")
    findings_upload = st.file_uploader("Findings CSV", type="csv")
    assets_upload = st.file_uploader("Asset inventory CSV", type="csv")
    config_upload = st.file_uploader("Policy / scoring YAML", type=["yaml", "yml"])
    live = st.toggle("Live NVD + EPSS + CISA KEV enrichment", value=False)
    st.caption("No uploads? RiskBridge uses the included demo data.")
    run = st.button("Run RiskBridge", type="primary", use_container_width=True)

if not run:
    st.info("Upload organization data or click **Run RiskBridge** to use the demo dataset.")
    st.stop()

try:
    findings = read_uploaded_csv(findings_upload, ROOT / "examples/findings.csv", load_findings)
    assets = read_uploaded_csv(assets_upload, ROOT / "examples/assets.csv", load_assets)
    config = load_config(config_upload)
    scored, zero_day = run_analysis(findings, assets, config, live=live)
except Exception as exc:
    st.error(f"Analysis failed: {exc}")
    st.stop()

weekly_hours = config.get("organization", {}).get("weekly_patch_capacity_hours")
optimizer = optimize_patch_bundles(scored, weekly_hours=weekly_hours)

m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Findings", len(scored))
m2.metric("P0", int((scored["priority"] == "P0").sum()) if not scored.empty else 0)
m3.metric("P1", int((scored["priority"] == "P1").sum()) if not scored.empty else 0)
m4.metric("Avg RiskBridge", f"{scored['riskbridge_score'].mean():.1f}" if not scored.empty else "0")
m5.metric("Critical ZD assets", int((zero_day["zero_day_exposure_rating"] == "CRITICAL").sum()) if not zero_day.empty else 0)

executive, vulnerabilities, zeroday_tab, optimization, quality = st.tabs(
    ["Executive", "Vulnerabilities", "Zero-Day Surface", "Optimization", "Data Quality"]
)

with executive:
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Risk dimensions — radial view")
        dims = ["Technical", "Threat", "Business", "Exposure", "Control Weakness"]
        control_mean = scored["control_effectiveness"].dropna().mean() if "control_effectiveness" in scored else 0
        vals = [
            scored["technical_score"].dropna().mean(),
            scored["threat_score"].dropna().mean(),
            scored["business_score"].dropna().mean(),
            scored["exposure_score"].dropna().mean(),
            100 - control_mean if pd.notna(control_mean) else 0,
        ]
        vals = [0 if pd.isna(v) else float(v) for v in vals]
        fig = go.Figure(go.Scatterpolar(r=vals + [vals[0]], theta=dims + [dims[0]], fill="toself"))
        fig.update_layout(polar=dict(radialaxis=dict(visible=True, range=[0, 100])), showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    with c2:
        st.subheader("Priority distribution")
        counts = scored["priority"].value_counts().rename_axis("priority").reset_index(name="count")
        fig = px.bar(counts, x="priority", y="count", text="count")
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Business risk vs exploitation likelihood")
    plot_df = scored.copy()
    plot_df["epss_display"] = pd.to_numeric(plot_df.get("epss"), errors="coerce")
    fig = px.scatter(
        plot_df,
        x="epss_display",
        y="riskbridge_score",
        size="business_score",
        hover_name="cve_id",
        hover_data=["hostname", "priority", "known_exploited", "confidence"],
        labels={"epss_display": "EPSS probability", "riskbridge_score": "RiskBridge score"},
    )
    st.plotly_chart(fig, use_container_width=True)

with vulnerabilities:
    st.subheader("Prioritized vulnerability decisions")
    wanted = [
        "priority", "riskbridge_score", "confidence", "cve_id", "hostname", "product",
        "cvss_score", "epss", "epss_percentile", "known_exploited", "technical_score",
        "threat_score", "business_score", "exposure_score", "control_effectiveness",
        "emerging_vulnerability_score", "patch_by", "top_risk_drivers", "exposure_hint", "data_gaps",
    ]
    st.dataframe(scored[[c for c in wanted if c in scored.columns]], use_container_width=True, hide_index=True)
    st.subheader("Top findings")
    top = scored.head(15).sort_values("riskbridge_score")
    fig = px.bar(top, x="riskbridge_score", y="cve_id", orientation="h", hover_data=["hostname", "priority"])
    st.plotly_chart(fig, use_container_width=True)

with zeroday_tab:
    if zero_day.empty:
        st.info("No asset data available for zero-day exposure modeling.")
    else:
        top_asset = zero_day.iloc[0]
        c1, c2 = st.columns(2)
        with c1:
            st.subheader("Highest pre-CVE exposure — radial gauge")
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=float(top_asset["zero_day_exposure_score"]),
                title={"text": f"{top_asset.get('hostname', top_asset.get('asset_id', 'Asset'))}"},
                gauge={"axis": {"range": [0, 100]}},
            ))
            st.plotly_chart(fig, use_container_width=True)
        with c2:
            st.subheader("Top asset — exposure dimensions")
            dims = ["Attack Surface", "Privilege & Reachability", "Software Exposure", "Business Impact", "Control Weakness"]
            vals = [
                top_asset.get("zd_attack_surface", 0), top_asset.get("zd_privilege_reachability", 0),
                top_asset.get("zd_software_exposure", 0), top_asset.get("zd_business_impact", 0),
                top_asset.get("zd_control_weakness", 0),
            ]
            vals = [0 if pd.isna(v) else float(v) for v in vals]
            fig = go.Figure(go.Scatterpolar(r=vals + [vals[0]], theta=dims + [dims[0]], fill="toself"))
            fig.update_layout(polar=dict(radialaxis=dict(visible=True, range=[0, 100])), showlegend=False)
            st.plotly_chart(fig, use_container_width=True)

        st.subheader("Zero-Day Exposure Surface Matrix")
        fig = px.scatter(
            zero_day,
            x="zd_attack_surface",
            y="zd_business_impact",
            size="zero_day_exposure_score",
            hover_name="hostname",
            hover_data=["zero_day_exposure_rating", "zero_day_drivers"],
            labels={"zd_attack_surface": "Attack surface", "zd_business_impact": "Business impact"},
        )
        fig.update_xaxes(range=[0, 100])
        fig.update_yaxes(range=[0, 100])
        st.plotly_chart(fig, use_container_width=True)
        st.dataframe(zero_day, use_container_width=True, hide_index=True)

with optimization:
    st.subheader("Patch bundle optimizer")
    st.caption("Optimization uses risk points removed per estimated remediation hour. It does not fabricate financial loss.")
    st.dataframe(optimizer, use_container_width=True, hide_index=True)
    if not optimizer.empty:
        fig = px.scatter(
            optimizer,
            x="estimated_hours",
            y="risk_points_removed",
            size="risk_points_per_hour",
            hover_name="product",
            hover_data=["cves", "schedule"] if "schedule" in optimizer.columns else ["cves"],
        )
        st.plotly_chart(fig, use_container_width=True)

with quality:
    st.subheader("Decision confidence")
    st.caption("Low confidence means RiskBridge is missing inputs; missing threat intelligence is never replaced with random data.")
    if not scored.empty:
        fig = px.histogram(scored, x="confidence", nbins=10)
        st.plotly_chart(fig, use_container_width=True)
        st.dataframe(scored[["cve_id", "hostname", "confidence", "data_gaps"]], use_container_width=True, hide_index=True)

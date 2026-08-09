from __future__ import annotations

from pathlib import Path
import re
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
from riskbridge.zero_day import zero_day_exposure

st.set_page_config(page_title="Riskbridge_Tool", page_icon="🌉", layout="wide")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)


def default_config() -> dict:
    return yaml.safe_load((ROOT / "config/default.yaml").read_text(encoding="utf-8")) or {}


def read_uploaded_csv(uploaded, fallback: Path, loader):
    if uploaded is None:
        return loader(fallback)
    tmp = ROOT / ".riskbridge_upload.csv"
    tmp.write_bytes(uploaded.getvalue())
    try:
        return loader(tmp)
    finally:
        tmp.unlink(missing_ok=True)


def load_config_upload(uploaded) -> dict:
    if uploaded is None:
        return default_config()
    return yaml.safe_load(uploaded.getvalue().decode("utf-8")) or {}


def parse_cves(text: str) -> tuple[list[str], list[str]]:
    tokens = re.split(r"[\s,;]+", text.upper().strip())
    unique: list[str] = []
    invalid: list[str] = []
    for token in tokens:
        if not token:
            continue
        if not CVE_RE.match(token):
            invalid.append(token)
            continue
        if token not in unique:
            unique.append(token)
    return unique, invalid


def radar_chart(labels: list[str], values: list[float], title: str):
    clean = [0.0 if pd.isna(v) else float(v) for v in values]
    fig = go.Figure(
        go.Scatterpolar(
            r=clean + [clean[0]],
            theta=labels + [labels[0]],
            fill="toself",
        )
    )
    fig.update_layout(
        title=title,
        polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
        showlegend=False,
        margin=dict(l=40, r=40, t=70, b=40),
    )
    return fig


def render_zero_day_results(zero_day: pd.DataFrame) -> None:
    if zero_day.empty:
        st.info("No asset data available for zero-day exposure modeling.")
        return

    top_asset = zero_day.iloc[0]
    c1, c2 = st.columns(2)

    with c1:
        fig = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=float(top_asset["zero_day_exposure_score"]),
                title={"text": str(top_asset.get("hostname", top_asset.get("asset_id", "Asset")))},
                gauge={"axis": {"range": [0, 100]}},
            )
        )
        fig.update_layout(title="Highest pre-CVE exposure — radial gauge")
        st.plotly_chart(fig, use_container_width=True)

    with c2:
        vals = [
            top_asset.get("zd_attack_surface", 0),
            top_asset.get("zd_privilege_reachability", 0),
            top_asset.get("zd_software_exposure", 0),
            top_asset.get("zd_business_impact", 0),
            top_asset.get("zd_control_weakness", 0),
        ]
        st.plotly_chart(
            radar_chart(
                [
                    "Attack Surface",
                    "Privilege & Reachability",
                    "Software Exposure",
                    "Business Impact",
                    "Control Weakness",
                ],
                vals,
                "Top asset — exposure dimensions",
            ),
            use_container_width=True,
        )

    st.subheader("Zero-Day Exposure Surface Matrix")
    fig = px.scatter(
        zero_day,
        x="zd_attack_surface",
        y="zd_business_impact",
        size="zero_day_exposure_score",
        hover_name="hostname" if "hostname" in zero_day.columns else "asset_id",
        hover_data=[
            c for c in ["zero_day_exposure_rating", "zero_day_drivers"] if c in zero_day.columns
        ],
        labels={
            "zd_attack_surface": "Attack surface",
            "zd_business_impact": "Business impact",
        },
    )
    fig.update_xaxes(range=[0, 100])
    fig.update_yaxes(range=[0, 100])
    st.plotly_chart(fig, use_container_width=True)
    st.dataframe(zero_day, use_container_width=True, hide_index=True)


def render_scored_results(scored: pd.DataFrame, zero_day: pd.DataFrame, config: dict) -> None:
    if scored.empty:
        st.warning("No vulnerability results were produced.")
        return

    weekly_hours = config.get("organization", {}).get("weekly_patch_capacity_hours")
    optimizer = optimize_patch_bundles(scored, weekly_hours=weekly_hours)

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Findings", len(scored))
    m2.metric("P0", int((scored["priority"] == "P0").sum()))
    m3.metric("P1", int((scored["priority"] == "P1").sum()))
    m4.metric("Avg RiskBridge", f"{scored['riskbridge_score'].mean():.1f}")
    m5.metric(
        "Critical ZD assets",
        int((zero_day["zero_day_exposure_rating"] == "CRITICAL").sum())
        if not zero_day.empty
        else 0,
    )

    executive, vulnerabilities, zeroday_tab, optimization, quality = st.tabs(
        ["Executive", "Vulnerabilities", "Zero-Day Surface", "Optimization", "Data Quality"]
    )

    with executive:
        c1, c2 = st.columns(2)

        with c1:
            control_mean = scored["control_effectiveness"].dropna().mean()
            vals = [
                scored["technical_score"].dropna().mean(),
                scored["threat_score"].dropna().mean(),
                scored["business_score"].dropna().mean(),
                scored["exposure_score"].dropna().mean(),
                100 - control_mean if pd.notna(control_mean) else 0,
            ]
            st.plotly_chart(
                radar_chart(
                    ["Technical", "Threat", "Business", "Exposure", "Control Weakness"],
                    vals,
                    "Risk dimensions — radial view",
                ),
                use_container_width=True,
            )

        with c2:
            counts = (
                scored["priority"]
                .value_counts()
                .rename_axis("priority")
                .reset_index(name="count")
            )
            fig = px.bar(
                counts,
                x="priority",
                y="count",
                text="count",
                title="Priority distribution",
            )
            st.plotly_chart(fig, use_container_width=True)

        st.subheader("Business risk vs exploitation likelihood")
        plot_df = scored.copy()
        plot_df["epss_display"] = pd.to_numeric(plot_df.get("epss"), errors="coerce")
        hover = [
            c for c in ["hostname", "priority", "known_exploited", "confidence"]
            if c in plot_df.columns
        ]
        fig = px.scatter(
            plot_df,
            x="epss_display",
            y="riskbridge_score",
            size="business_score",
            hover_name="cve_id",
            hover_data=hover,
            labels={
                "epss_display": "EPSS probability",
                "riskbridge_score": "RiskBridge score",
            },
        )
        st.plotly_chart(fig, use_container_width=True)

    with vulnerabilities:
        st.subheader("Prioritized vulnerability decisions")
        wanted = [
            "priority",
            "riskbridge_score",
            "confidence",
            "cve_id",
            "hostname",
            "product",
            "cvss_score",
            "cvss_severity",
            "epss",
            "epss_percentile",
            "known_exploited",
            "technical_score",
            "threat_score",
            "business_score",
            "exposure_score",
            "control_effectiveness",
            "emerging_vulnerability_score",
            "patch_by",
            "top_risk_drivers",
            "exposure_hint",
            "data_gaps",
            "intelligence_errors",
        ]
        st.dataframe(
            scored[[c for c in wanted if c in scored.columns]],
            use_container_width=True,
            hide_index=True,
        )

        top = scored.head(15).sort_values("riskbridge_score")
        fig = px.bar(
            top,
            x="riskbridge_score",
            y="cve_id",
            orientation="h",
            hover_data=[c for c in ["hostname", "priority"] if c in top.columns],
            title="Top findings",
        )
        st.plotly_chart(fig, use_container_width=True)

    with zeroday_tab:
        render_zero_day_results(zero_day)

    with optimization:
        st.subheader("Patch bundle optimizer")
        st.caption(
            "Ranks actions by risk points removed per estimated remediation hour; "
            "no fabricated financial loss."
        )
        st.dataframe(optimizer, use_container_width=True, hide_index=True)

        if not optimizer.empty:
            hover = ["cves"] + (["schedule"] if "schedule" in optimizer.columns else [])
            fig = px.scatter(
                optimizer,
                x="estimated_hours",
                y="risk_points_removed",
                size="risk_points_per_hour",
                hover_name="product",
                hover_data=hover,
                title="Remediation efficiency frontier",
            )
            st.plotly_chart(fig, use_container_width=True)

    with quality:
        st.subheader("Decision confidence")
        st.caption(
            "Missing intelligence lowers confidence; RiskBridge does not invent "
            "replacement security data."
        )
        fig = px.histogram(scored, x="confidence", nbins=10)
        st.plotly_chart(fig, use_container_width=True)
        cols = [
            c for c in [
                "cve_id",
                "hostname",
                "confidence",
                "data_gaps",
                "intelligence_errors",
            ]
            if c in scored.columns
        ]
        st.dataframe(scored[cols], use_container_width=True, hide_index=True)


def asset_context_form(prefix: str = "quick") -> dict:
    c1, c2, c3 = st.columns(3)

    with c1:
        hostname = st.text_input(
            "Hostname / asset name",
            value="example-asset-01",
            key=f"{prefix}_hostname",
        )
        environment = st.selectbox(
            "Environment",
            ["production", "staging", "development", "test"],
            key=f"{prefix}_environment",
        )
        criticality = st.slider(
            "Business criticality", 1, 5, 4, key=f"{prefix}_criticality"
        )
        data_sensitivity = st.slider(
            "Data sensitivity", 1, 5, 3, key=f"{prefix}_data"
        )
        revenue_impact = st.slider(
            "Revenue impact", 1, 5, 3, key=f"{prefix}_revenue"
        )
        safety_impact = st.slider(
            "Safety impact", 1, 5, 1, key=f"{prefix}_safety"
        )

    with c2:
        internet_exposed = st.checkbox(
            "Internet exposed", value=True, key=f"{prefix}_internet"
        )
        public_api = st.checkbox(
            "Public API", value=False, key=f"{prefix}_api"
        )
        remote_access = st.checkbox(
            "Remote access", value=False, key=f"{prefix}_remote"
        )
        privileged = st.checkbox(
            "Privileged system/service", value=False, key=f"{prefix}_priv"
        )
        third_party_exposure = st.checkbox(
            "Third-party exposure", value=True, key=f"{prefix}_thirdparty"
        )
        unsupported_software = st.checkbox(
            "Unsupported software", value=False, key=f"{prefix}_unsupported"
        )
        network_reachability = st.slider(
            "Network reachability", 1, 5, 3, key=f"{prefix}_reach"
        )
        identity_criticality = st.slider(
            "Identity criticality", 1, 5, 2, key=f"{prefix}_identity"
        )
        open_ports = st.number_input(
            "Open ports / exposed services",
            min_value=0,
            max_value=100,
            value=4,
            key=f"{prefix}_ports",
        )
        technology_age_years = st.number_input(
            "Technology age (years)",
            min_value=0.0,
            max_value=50.0,
            value=3.0,
            step=0.5,
            key=f"{prefix}_age",
        )

    with c3:
        st.markdown("**Control effectiveness (1 = weak, 5 = strong)**")
        segmentation = st.slider(
            "Segmentation", 1, 5, 3, key=f"{prefix}_seg"
        )
        edr = st.slider(
            "EDR", 1, 5, 3, key=f"{prefix}_edr"
        )
        waf = st.slider(
            "WAF / application protection", 1, 5, 3, key=f"{prefix}_waf"
        )
        least_privilege = st.slider(
            "Least privilege", 1, 5, 3, key=f"{prefix}_lp"
        )
        monitoring = st.slider(
            "Monitoring / detection", 1, 5, 3, key=f"{prefix}_monitor"
        )

    return {
        "asset_id": f"{prefix.upper()}-001",
        "hostname": hostname,
        "business_service": "User-entered",
        "environment": environment,
        "criticality": criticality,
        "data_sensitivity": data_sensitivity,
        "revenue_impact": revenue_impact,
        "safety_impact": safety_impact,
        "internet_exposed": internet_exposed,
        "privileged": privileged,
        "network_reachability": network_reachability,
        "identity_criticality": identity_criticality,
        "open_ports": int(open_ports),
        "public_api": public_api,
        "remote_access": remote_access,
        "unsupported_software": unsupported_software,
        "technology_age_years": float(technology_age_years),
        "third_party_exposure": third_party_exposure,
        "segmentation_effectiveness": segmentation,
        "edr_effectiveness": edr,
        "waf_effectiveness": waf,
        "least_privilege_effectiveness": least_privilege,
        "monitoring_effectiveness": monitoring,
    }


st.title("Riskbridge_Tool")
st.caption(
    "From CVE intelligence to business-aligned remediation decisions — "
    "plus pre-CVE zero-day exposure modeling"
)

mode = st.radio(
    "What would you like to do?",
    [
        "🔎 Quick CVE Analysis",
        "🏢 Organization CSV Analysis",
        "⚡ Zero-Day Asset Analysis",
        "📊 Demo",
    ],
    horizontal=True,
)

config = default_config()

if mode == "🔎 Quick CVE Analysis":
    st.header("Quick CVE Analysis")
    st.write(
        "Enter one or more CVE IDs. RiskBridge retrieves live NVD, EPSS and "
        "CISA KEV intelligence and combines it with your business context."
    )

    cve_text = st.text_area(
        "CVE IDs",
        placeholder="CVE-2024-3094\nCVE-2021-44228\nCVE-2023-44487",
        height=130,
    )

    remediation_hours = st.number_input(
        "Estimated remediation effort per CVE (hours)",
        min_value=0.1,
        value=2.0,
        step=0.5,
    )

    with st.expander("Business and asset context", expanded=True):
        asset = asset_context_form("quick")

    if st.button("Analyze CVEs", type="primary", use_container_width=True):
        cves, invalid = parse_cves(cve_text)

        if invalid:
            st.error("Invalid CVE IDs: " + ", ".join(invalid))
        elif not cves:
            st.warning("Enter at least one CVE ID, for example CVE-2024-3094.")
        else:
            findings = pd.DataFrame(
                [
                    {
                        "finding_id": f"QUICK-{i:03d}",
                        "asset_id": asset["asset_id"],
                        "cve_id": cid,
                        "product": "",
                        "port": None,
                        "protocol": "",
                        "first_seen": "",
                        "remediation_hours": float(remediation_hours),
                    }
                    for i, cid in enumerate(cves, start=1)
                ]
            )
            assets = pd.DataFrame([asset])

            with st.spinner(
                "Retrieving NVD, EPSS and CISA KEV intelligence and calculating business risk..."
            ):
                scored, zero_day = run_analysis(
                    findings,
                    assets,
                    config,
                    live=True,
                )

            render_scored_results(scored, zero_day, config)

elif mode == "🏢 Organization CSV Analysis":
    st.header("Organization CSV Analysis")
    st.write(
        "Use this mode for vulnerability exports and asset inventories. "
        "Generic CSV works today; scanner adapters can be added later."
    )

    c1, c2 = st.columns(2)

    with c1:
        findings_upload = st.file_uploader("Findings CSV", type="csv")

    with c2:
        assets_upload = st.file_uploader("Asset inventory CSV", type="csv")

    config_upload = st.file_uploader(
        "Policy / scoring YAML (optional)",
        type=["yaml", "yml"],
    )

    live = st.toggle(
        "Live NVD + EPSS + CISA KEV enrichment",
        value=True,
    )

    use_demo_if_missing = st.checkbox(
        "Use included demo data if no files are uploaded",
        value=False,
    )

    if st.button(
        "Run organization analysis",
        type="primary",
        use_container_width=True,
    ):
        if (
            findings_upload is None or assets_upload is None
        ) and not use_demo_if_missing:
            st.warning(
                "Upload both CSV files, or enable the demo-data option."
            )
        else:
            findings = read_uploaded_csv(
                findings_upload,
                ROOT / "examples/findings.csv",
                load_findings,
            )
            assets = read_uploaded_csv(
                assets_upload,
                ROOT / "examples/assets.csv",
                load_assets,
            )
            org_config = load_config_upload(config_upload)

            with st.spinner("Analyzing organization data..."):
                scored, zero_day = run_analysis(
                    findings,
                    assets,
                    org_config,
                    live=live,
                )

            render_scored_results(scored, zero_day, org_config)

elif mode == "⚡ Zero-Day Asset Analysis":
    st.header("Pre-CVE Zero-Day Exposure")
    st.write(
        "No CVE is required. Describe an asset and RiskBridge estimates where "
        "an unknown vulnerability could create the greatest exposure."
    )

    asset = asset_context_form("zeroday")

    if st.button(
        "Calculate zero-day exposure",
        type="primary",
        use_container_width=True,
    ):
        result = {
            **asset,
            **zero_day_exposure(pd.Series(asset), config),
        }
        zero_day_df = pd.DataFrame([result])

        score = result["zero_day_exposure_score"]
        rating = result["zero_day_exposure_rating"]

        st.success(
            f"Zero-Day Exposure Score: {score:.1f}/100 — {rating}"
        )

        render_zero_day_results(zero_day_df)

else:
    st.header("RiskBridge Demo")
    st.write(
        "Run the included sample environment to explore every view "
        "without preparing any files."
    )

    live_demo = st.toggle(
        "Refresh demo with live NVD + EPSS + CISA KEV intelligence",
        value=False,
    )

    if st.button("Run Demo", type="primary", use_container_width=True):
        findings = load_findings(ROOT / "examples/findings.csv")
        assets = load_assets(ROOT / "examples/assets.csv")

        with st.spinner("Running RiskBridge demo..."):
            scored, zero_day = run_analysis(
                findings,
                assets,
                config,
                live=live_demo,
            )

        render_scored_results(scored, zero_day, config)

st.divider()
st.caption(
    "RiskBridge is decision support. EPSS is not a business-risk score, "
    "KEV absence does not imply safety, and the zero-day model measures "
    "exposure rather than predicting an unknown CVE."
)

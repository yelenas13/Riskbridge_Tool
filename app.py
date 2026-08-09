from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path
import json
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

from riskbridge.attack_paths import exposure_paths
from riskbridge.consensus import consensus_summary
from riskbridge.connectors import load_assets, load_findings
from riskbridge.exceptions import exception_record
from riskbridge.ml import (
    explain_prediction,
    model_to_bytes,
    train_exploitation_model,
)
from riskbridge.optimizer import optimize_patch_bundles
from riskbridge.pipeline import run_analysis
from riskbridge.services import business_service_summary
from riskbridge.simulator import simulate_interventions
from riskbridge.validation import compare_rankings
from riskbridge.utils import as_bool
from riskbridge.zero_day import zero_day_exposure

st.set_page_config(page_title="Riskbridge_Tool", page_icon="🌉", layout="wide")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)


def default_config() -> dict:
    return yaml.safe_load((ROOT / "config/default.yaml").read_text(encoding="utf-8")) or {}


def uploaded_csv(uploaded) -> pd.DataFrame:
    return pd.read_csv(uploaded) if uploaded is not None else pd.DataFrame()


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


def active_ml_bundle():
    """Use only a model trained in this Streamlit session.

    The public app intentionally does not deserialize arbitrary pickle/joblib uploads.
    """
    return st.session_state.get("reem_bundle")


def radar_chart(labels: list[str], values: list[float], title: str):
    clean = [0.0 if v is None or pd.isna(v) else float(v) for v in values]
    if not clean:
        clean = [0.0] * len(labels)
    fig = go.Figure(
        go.Scatterpolar(r=clean + [clean[0]], theta=labels + [labels[0]], fill="toself")
    )
    fig.update_layout(
        title=title,
        polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
        showlegend=False,
        margin=dict(l=40, r=40, t=70, b=40),
    )
    return fig


def render_epss_history(row: pd.Series) -> None:
    raw = row.get("epss_history_json")
    if not raw:
        st.caption("EPSS history was not available for this analysis.")
        return
    try:
        history = pd.DataFrame(json.loads(str(raw)))
        if history.empty:
            st.caption("EPSS history was not available for this analysis.")
            return
        history["date"] = pd.to_datetime(history["date"], errors="coerce")
        history["epss"] = pd.to_numeric(history["epss"], errors="coerce")
        fig = px.line(history.sort_values("date"), x="date", y="epss", markers=True, title="EPSS 30-day movement")
        fig.update_yaxes(range=[0, 1], tickformat=".1%")
        st.plotly_chart(fig, use_container_width=True)
    except Exception:
        st.caption("EPSS history could not be rendered.")


def source_links(row: pd.Series) -> None:
    links: list[tuple[str, str]] = []
    if row.get("nvd_url"):
        links.append(("NVD", str(row.get("nvd_url"))))
    for label, field in (
        ("Vendor advisory", "vendor_advisory_urls"),
        ("Patch reference", "patch_reference_urls"),
        ("Mitigation reference", "mitigation_reference_urls"),
    ):
        for url in str(row.get(field) or "").split(" | "):
            if url.strip():
                links.append((label, url.strip()))
    if links:
        st.markdown("**Evidence / source links**")
        for label, url in links[:8]:
            st.markdown(f"- [{label}]({url})")


def render_decision_card(row: pd.Series, config: dict, ml_bundle=None, key_prefix: str = "card") -> None:
    cve = str(row.get("cve_id") or "CVE")
    host = str(row.get("hostname") or row.get("asset_id") or "asset")
    title = str(row.get("kev_vulnerability_name") or "").strip()
    label = f"{cve} — {title}" if title else f"{cve} on {host}"

    with st.expander(label, expanded=True):
        m1, m2, m3, m4, m5, m6 = st.columns(6)
        m1.metric("RiskBridge", f"{float(row.get('riskbridge_score') or 0):.1f}/100")
        m2.metric("Priority", str(row.get("priority") or "—"))
        m3.metric("Confidence", f"{float(row.get('confidence') or 0):.0f}%")
        m4.metric("Applicability", str(row.get("applicability_status") or "UNKNOWN"))
        epss = row.get("epss")
        m5.metric("EPSS", f"{float(epss):.2%}" if pd.notna(epss) else "N/A")
        m6.metric("KEV", "YES" if as_bool(row.get("known_exploited")) else "NO")

        description = str(row.get("description_short") or row.get("description") or "No NVD description was available.")
        st.markdown("#### What this CVE is")
        st.write(description)
        if row.get("cwe"):
            st.caption(f"Weakness: {row.get('cwe')}  •  CVSS: {row.get('cvss_version')} {row.get('cvss_score')} {row.get('cvss_severity') or ''}")

        applicability = str(row.get("applicability_status") or "UNKNOWN")
        if applicability == "CONFIRMED":
            st.success(str(row.get("applicability_reason") or "Applicability confirmed."))
        elif applicability == "OUT_OF_RANGE":
            st.info(str(row.get("applicability_reason") or "Version appears outside the vulnerable range."))
        else:
            st.warning(str(row.get("applicability_reason") or "Applicability is not confirmed; the risk score assumes the CVE applies."))

        c1, c2 = st.columns(2)
        with c1:
            st.markdown("#### Where to look in the environment")
            st.write(f"**Affected products from NVD:** {row.get('affected_products_nvd') or 'Not available'}")
            st.write(f"**Component type:** {row.get('component_type') or 'Unknown'}")
            st.write(f"**Search terms:** {row.get('inventory_search_terms') or 'Not available'}")
            st.write(str(row.get("where_to_look") or "Use inventory/SBOM/vendor tooling to identify the affected component."))
            if row.get("verification_commands"):
                st.code(str(row.get("verification_commands")), language="powershell" if str(row.get("os_family") or "").lower().startswith("win") else "bash")
            st.caption(str(row.get("detection_note") or ""))

        with c2:
            st.markdown("#### Recommended remediation")
            st.success(str(row.get("remediation_primary") or "Follow the vendor-supported remediation."))
            if row.get("fixed_version_hint"):
                st.write(f"**Version guidance:** {row.get('fixed_version_hint')}")
            st.write(str(row.get("remediation_secondary") or ""))
            st.write(f"**Remediation evidence confidence:** {row.get('remediation_confidence') or 'N/A'}")
            st.caption(f"Basis: {row.get('remediation_source') or 'NVD/CISA/vendor references'}")
            st.write(f"**Validate closure:** {row.get('remediation_validation') or ''}")
            if row.get("kev_required_action"):
                st.warning(f"CISA KEV required action: {row.get('kev_required_action')}")

        st.markdown("#### Why RiskBridge prioritized it")
        st.write(str(row.get("top_risk_drivers") or "Insufficient data"))
        st.caption(str(row.get("decision_note") or ""))

        dims = ["Technical", "Threat", "Business", "Exposure", "Control Weakness"]
        controls = row.get("control_effectiveness")
        vals = [
            row.get("technical_score"),
            row.get("threat_score"),
            row.get("business_score"),
            row.get("exposure_score"),
            100 - float(controls) if controls is not None and pd.notna(controls) else 0,
        ]
        c3, c4 = st.columns(2)
        with c3:
            st.plotly_chart(radar_chart(dims, vals, "Risk dimensions"), use_container_width=True)
        with c4:
            render_epss_history(row)

        if row.get("epss_trend"):
            st.write(
                f"**EPSS trend:** {row.get('epss_trend')}  |  "
                f"7-day Δ: {row.get('epss_delta_7d') if pd.notna(row.get('epss_delta_7d')) else 'N/A'}  |  "
                f"30-day Δ: {row.get('epss_delta_30d') if pd.notna(row.get('epss_delta_30d')) else 'N/A'}"
            )

        ml_p = row.get("ml_exploitation_probability")
        if ml_p is not None and pd.notna(ml_p):
            st.markdown("#### ML threat signal — REEM")
            st.metric("Model-estimated exploitation probability", f"{float(ml_p):.2%}")
            st.caption("This ML probability contributes only to the threat dimension; it does not directly decide P0/P1/P2/P3.")
            if ml_bundle:
                try:
                    explanation = explain_prediction(ml_bundle, row)
                    exp_df = pd.DataFrame(explanation, columns=["feature", "log_odds_contribution"])
                    st.dataframe(exp_df, hide_index=True, use_container_width=True)
                except Exception as exc:
                    st.caption(f"ML explanation unavailable: {exc}")

        source_links(row)


def render_zero_day_results(zero_day: pd.DataFrame) -> None:
    if zero_day is None or zero_day.empty:
        st.info("No asset data available for pre-CVE exposure modeling.")
        return

    top_asset = zero_day.iloc[0]
    c1, c2, c3 = st.columns(3)
    with c1:
        fig = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=float(top_asset["zero_day_exposure_score"]),
                title={"text": "Pre-CVE Exposure"},
                gauge={"axis": {"range": [0, 100]}},
            )
        )
        st.plotly_chart(fig, use_container_width=True)
    with c2:
        prep = top_asset.get("zero_day_preparedness_score")
        if prep is not None and pd.notna(prep):
            fig = go.Figure(
                go.Indicator(
                    mode="gauge+number",
                    value=float(prep),
                    title={"text": "Zero-Day Preparedness"},
                    gauge={"axis": {"range": [0, 100]}},
                )
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Preparedness inputs were not supplied for this asset.")
    with c3:
        vals = [
            top_asset.get("zd_attack_surface", 0),
            top_asset.get("zd_privilege_reachability", 0),
            top_asset.get("zd_software_exposure", 0),
            top_asset.get("zd_business_impact", 0),
            top_asset.get("zd_control_weakness", 0),
        ]
        st.plotly_chart(
            radar_chart(
                ["Attack Surface", "Privilege & Reachability", "Software Exposure", "Business Impact", "Control Weakness"],
                vals,
                "Exposure dimensions",
            ),
            use_container_width=True,
        )

    st.write(f"**Top exposure drivers:** {top_asset.get('zero_day_drivers') or 'N/A'}")
    if top_asset.get("zero_day_preparedness_drivers"):
        st.write(f"**Preparedness gaps:** {top_asset.get('zero_day_preparedness_drivers')}")

    st.subheader("Zero-Day Exposure Surface Matrix")
    fig = px.scatter(
        zero_day,
        x="zd_attack_surface",
        y="zd_business_impact",
        size="zero_day_exposure_score",
        hover_name="hostname" if "hostname" in zero_day.columns else "asset_id",
        hover_data=[c for c in ["zero_day_exposure_rating", "zero_day_preparedness_score", "zero_day_drivers"] if c in zero_day.columns],
        labels={"zd_attack_surface": "Attack surface", "zd_business_impact": "Business impact"},
    )
    fig.update_xaxes(range=[0, 100])
    fig.update_yaxes(range=[0, 100])
    st.plotly_chart(fig, use_container_width=True)
    st.dataframe(zero_day, use_container_width=True, hide_index=True)


def render_exception_workflow(scored: pd.DataFrame) -> None:
    st.subheader("Risk exception / acceptance record")
    st.caption("Acceptance is governance. It never reduces the RiskBridge risk score.")
    if "riskbridge_exceptions" not in st.session_state:
        st.session_state["riskbridge_exceptions"] = []
    if scored.empty:
        return
    choices = [f"{r.cve_id} | {r.hostname} | {r.asset_id}" for r in scored.itertuples()]
    selected = st.selectbox("Finding", choices)
    idx = choices.index(selected)
    row = scored.iloc[idx]
    c1, c2 = st.columns(2)
    with c1:
        owner = st.text_input("Exception owner")
        approver = st.text_input("Approver")
        expiry = st.date_input("Accept until", value=date.today() + timedelta(days=90))
    with c2:
        reason = st.text_area("Business justification")
        controls = st.text_area("Compensating controls")
    if st.button("Create exception record"):
        if not owner.strip() or not reason.strip():
            st.warning("Owner and business justification are required.")
        else:
            st.session_state["riskbridge_exceptions"].append(
                exception_record(
                    cve_id=str(row.get("cve_id")),
                    asset_id=str(row.get("asset_id")),
                    owner=owner,
                    reason=reason,
                    accept_until=expiry.isoformat(),
                    compensating_controls=controls,
                    approver=approver,
                )
            )
            st.success("Exception record created in this session. Export it and route it through your organization's approval process.")
    if st.session_state["riskbridge_exceptions"]:
        ex_df = pd.DataFrame(st.session_state["riskbridge_exceptions"])
        st.dataframe(ex_df, use_container_width=True, hide_index=True)
        st.download_button("Download exception CSV", ex_df.to_csv(index=False), "riskbridge_exceptions.csv", "text/csv")


def render_scored_results(
    scored: pd.DataFrame,
    zero_day: pd.DataFrame,
    config: dict,
    *,
    assets: pd.DataFrame | None = None,
    relationships: pd.DataFrame | None = None,
    vendor_scores: pd.DataFrame | None = None,
    ml_bundle=None,
) -> None:
    if scored.empty:
        st.warning("No vulnerability results were produced.")
        return

    weekly_hours = config.get("organization", {}).get("weekly_patch_capacity_hours")
    optimizer = optimize_patch_bundles(scored[scored["priority"] != "NA"], weekly_hours=weekly_hours)

    m1, m2, m3, m4, m5, m6 = st.columns(6)
    m1.metric("Findings", len(scored))
    m2.metric("P0", int((scored["priority"] == "P0").sum()))
    m3.metric("P1", int((scored["priority"] == "P1").sum()))
    m4.metric("Not applicable", int((scored["priority"] == "NA").sum()))
    m5.metric("Avg RiskBridge", f"{scored['riskbridge_score'].mean():.1f}")
    m6.metric("Avg Confidence", f"{scored['confidence'].mean():.0f}%")

    st.download_button("Download prioritized findings CSV", scored.to_csv(index=False), "prioritized_vulnerabilities.csv", "text/csv")

    tabs = st.tabs([
        "Executive",
        "Decision Cards",
        "Vulnerabilities",
        "Pre-CVE / Zero-Day",
        "What-If & Optimization",
        "Business Services & Paths",
        "Governance",
        "Data Quality",
    ])

    with tabs[0]:
        c1, c2 = st.columns(2)
        with c1:
            controls = scored["control_effectiveness"].dropna().mean()
            vals = [
                scored["technical_score"].dropna().mean(),
                scored["threat_score"].dropna().mean(),
                scored["business_score"].dropna().mean(),
                scored["exposure_score"].dropna().mean(),
                100 - controls if pd.notna(controls) else 0,
            ]
            st.plotly_chart(
                radar_chart(["Technical", "Threat", "Business", "Exposure", "Control Weakness"], vals, "Portfolio risk dimensions"),
                use_container_width=True,
            )
        with c2:
            counts = scored["priority"].value_counts().rename_axis("priority").reset_index(name="count")
            st.plotly_chart(px.bar(counts, x="priority", y="count", text="count", title="Priority distribution"), use_container_width=True)

        plot_df = scored[scored["priority"] != "NA"].copy()
        plot_df["epss_display"] = pd.to_numeric(plot_df.get("epss"), errors="coerce")
        if not plot_df.empty:
            st.plotly_chart(
                px.scatter(
                    plot_df,
                    x="epss_display",
                    y="riskbridge_score",
                    size="business_score",
                    hover_name="cve_id",
                    hover_data=[c for c in ["hostname", "priority", "known_exploited", "confidence", "applicability_status"] if c in plot_df.columns],
                    labels={"epss_display": "EPSS probability", "riskbridge_score": "RiskBridge score"},
                    title="Threat likelihood vs business-aligned risk",
                ),
                use_container_width=True,
            )

    with tabs[1]:
        for idx, row in scored.head(30).iterrows():
            render_decision_card(row, config, ml_bundle=ml_bundle, key_prefix=f"card_{idx}")

    with tabs[2]:
        wanted = [
            "priority", "riskbridge_score", "confidence", "decision_status", "applicability_status", "cve_id", "hostname",
            "asset_product_resolved", "asset_version_resolved", "cvss_score", "epss", "epss_percentile", "epss_trend",
            "known_exploited", "ml_exploitation_probability", "technical_score", "threat_score", "business_score",
            "exposure_score", "control_effectiveness", "emerging_vulnerability_score", "patch_by", "remediation_primary",
            "top_risk_drivers", "data_gaps",
        ]
        st.dataframe(scored[[c for c in wanted if c in scored.columns]], use_container_width=True, hide_index=True)

    with tabs[3]:
        st.info("This view is asset-based and independent of the CVE entered. It measures exposure to an unknown future vulnerability, not the probability that a zero-day exists.")
        render_zero_day_results(zero_day)

    with tabs[4]:
        choices = [f"{r.cve_id} | {r.hostname}" for r in scored.itertuples() if r.priority != "NA"]
        if choices:
            selected = st.selectbox("What-if finding", choices, key="whatif_select")
            row = scored[scored["priority"] != "NA"].iloc[choices.index(selected)]
            sim = simulate_interventions(row, config)
            st.subheader("What-if control simulator")
            st.caption("These are modeled score changes under stated assumptions, not guaranteed real-world loss reduction.")
            st.dataframe(sim, use_container_width=True, hide_index=True)
            st.plotly_chart(px.bar(sim, x="risk_reduction", y="action", orientation="h", title="Modeled risk reduction by intervention"), use_container_width=True)

        st.subheader("Patch / remediation bundle optimizer")
        st.dataframe(optimizer, use_container_width=True, hide_index=True)
        if not optimizer.empty:
            st.plotly_chart(
                px.scatter(
                    optimizer,
                    x="estimated_hours",
                    y="risk_points_removed",
                    size="risk_points_per_hour",
                    hover_name="product",
                    hover_data=["cves"] + (["schedule"] if "schedule" in optimizer.columns else []),
                    title="Risk reduction vs remediation effort",
                ),
                use_container_width=True,
            )

    with tabs[5]:
        services = business_service_summary(scored, zero_day)
        if services.empty:
            st.info("Add business_service to the asset inventory to enable service-level rollups.")
        else:
            st.subheader("Business service risk")
            st.dataframe(services, use_container_width=True, hide_index=True)
            st.plotly_chart(px.bar(services, x="business_service", y="max_risk", hover_data=["p0", "p1", "assets", "findings"], title="Maximum known-CVE risk by business service"), use_container_width=True)

        if vendor_scores is not None and not vendor_scores.empty:
            st.subheader("Scanner/vendor score consensus & disagreement")
            cons = consensus_summary(vendor_scores)
            st.dataframe(cons, use_container_width=True, hide_index=True)
            flagged = cons[cons["vendor_disagreement"] >= 30]
            if not flagged.empty:
                st.warning(f"{len(flagged)} item(s) have ≥30-point disagreement across vendor scores. Review before relying on a single scanner ranking.")

        if assets is not None and relationships is not None and not relationships.empty:
            st.subheader("Attack-Path Lite — structural exposure paths")
            try:
                paths = exposure_paths(assets, relationships, scored, zero_day)
                if paths.empty:
                    st.info("No structural path was found from an internet-exposed asset to a critical/crown-jewel asset using the uploaded relationships.")
                else:
                    st.warning("These are declared connectivity/dependency paths, not verified exploit chains.")
                    st.dataframe(paths, use_container_width=True, hide_index=True)
            except Exception as exc:
                st.error(f"Could not analyze relationships: {exc}")
        else:
            st.caption("Upload a relationships CSV in Organization mode to enable Attack-Path Lite.")

    with tabs[6]:
        render_exception_workflow(scored)

    with tabs[7]:
        st.subheader("Decision confidence and provenance")
        st.caption("Low confidence means missing, stale, or unverified context; RiskBridge does not replace missing security intelligence with random values.")
        st.plotly_chart(px.histogram(scored, x="confidence", nbins=10, title="Decision confidence"), use_container_width=True)
        cols = [c for c in ["cve_id", "hostname", "confidence", "applicability_status", "data_gaps", "intelligence_errors", "provenance"] if c in scored.columns]
        st.dataframe(scored[cols], use_container_width=True, hide_index=True)


def asset_context_form(prefix: str = "quick", *, preparedness: bool = True) -> dict:
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown("**Business context**")
        hostname = st.text_input("Hostname / asset name", value="example-asset-01", key=f"{prefix}_hostname")
        business_service = st.text_input("Business service", value="Example Service", key=f"{prefix}_service")
        environment = st.selectbox("Environment", ["production", "staging", "development", "test"], key=f"{prefix}_environment")
        criticality = st.slider("Business criticality", 1, 5, 4, key=f"{prefix}_criticality")
        data_sensitivity = st.slider("Data sensitivity", 1, 5, 3, key=f"{prefix}_data")
        revenue_impact = st.slider("Revenue impact", 1, 5, 3, key=f"{prefix}_revenue")
        safety_impact = st.slider("Safety impact", 1, 5, 1, key=f"{prefix}_safety")

    with c2:
        st.markdown("**Software / applicability**")
        asset_vendor = st.text_input("Vendor (optional)", value="", key=f"{prefix}_vendor")
        asset_product = st.text_input("Product / package (recommended)", value="", key=f"{prefix}_product")
        asset_version = st.text_input("Installed version (recommended)", value="", key=f"{prefix}_version")
        os_family = st.selectbox("OS / platform", ["unknown", "linux", "windows", "macos", "appliance", "container"], key=f"{prefix}_os")
        unsupported_software = st.checkbox("Unsupported software", value=False, key=f"{prefix}_unsupported")
        technology_age_years = st.number_input("Technology age (years)", min_value=0.0, max_value=50.0, value=3.0, step=0.5, key=f"{prefix}_age")
        third_party_exposure = st.checkbox("Third-party exposure", value=True, key=f"{prefix}_thirdparty")

    with c3:
        st.markdown("**Exposure**")
        internet_exposed = st.checkbox("Internet exposed", value=True, key=f"{prefix}_internet")
        public_api = st.checkbox("Public API", value=False, key=f"{prefix}_api")
        remote_access = st.checkbox("Remote access", value=False, key=f"{prefix}_remote")
        privileged = st.checkbox("Privileged system/service", value=False, key=f"{prefix}_priv")
        network_reachability = st.slider("Network reachability", 1, 5, 3, key=f"{prefix}_reach")
        identity_criticality = st.slider("Identity criticality", 1, 5, 2, key=f"{prefix}_identity")
        open_ports = st.number_input("Open ports / exposed services", min_value=0, max_value=100, value=4, key=f"{prefix}_ports")

    with c4:
        st.markdown("**Control effectiveness (1=weak, 5=strong)**")
        segmentation = st.slider("Segmentation", 1, 5, 3, key=f"{prefix}_seg")
        edr = st.slider("EDR", 1, 5, 3, key=f"{prefix}_edr")
        waf = st.slider("WAF / application protection", 1, 5, 3, key=f"{prefix}_waf")
        least_privilege = st.slider("Least privilege", 1, 5, 3, key=f"{prefix}_lp")
        monitoring = st.slider("Monitoring / detection", 1, 5, 3, key=f"{prefix}_monitor")

    readiness = {
        "isolation_readiness": None,
        "emergency_patching_readiness": None,
        "recovery_readiness": None,
        "inventory_accuracy": None,
        "telemetry_readiness": None,
        "change_flexibility": None,
    }
    if preparedness:
        with st.expander("Zero-day preparedness inputs (optional but recommended)"):
            p1, p2, p3 = st.columns(3)
            with p1:
                readiness["isolation_readiness"] = st.slider("Emergency isolation readiness", 1, 5, 3, key=f"{prefix}_isolation")
                readiness["emergency_patching_readiness"] = st.slider("Emergency patching readiness", 1, 5, 3, key=f"{prefix}_empatch")
            with p2:
                readiness["recovery_readiness"] = st.slider("Recovery readiness", 1, 5, 3, key=f"{prefix}_recovery")
                readiness["inventory_accuracy"] = st.slider("Inventory / SBOM accuracy", 1, 5, 3, key=f"{prefix}_inventory")
            with p3:
                readiness["telemetry_readiness"] = st.slider("Telemetry readiness", 1, 5, 3, key=f"{prefix}_telemetry")
                readiness["change_flexibility"] = st.slider("Emergency change flexibility", 1, 5, 3, key=f"{prefix}_change")

    return {
        "asset_id": f"{prefix.upper()}-001",
        "hostname": hostname,
        "business_service": business_service,
        "environment": environment,
        "criticality": criticality,
        "data_sensitivity": data_sensitivity,
        "revenue_impact": revenue_impact,
        "safety_impact": safety_impact,
        "asset_vendor": asset_vendor,
        "asset_product": asset_product,
        "asset_version": asset_version,
        "os_family": os_family,
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
        **readiness,
    }


st.title("Riskbridge_Tool")
st.caption("Explainable cyber-risk decisions for known vulnerabilities, emerging threats, and pre-CVE exposure")

with st.sidebar:
    st.header("RiskBridge v0.4")
    ml_bundle = active_ml_bundle()
    if ml_bundle:
        meta = ml_bundle.get("metadata", {})
        st.success(f"Session ML active: {meta.get('model_name', 'REEM')}")
        if meta.get("metrics"):
            st.caption(f"Held-out PR-AUC: {meta['metrics'].get('pr_auc')}")
    else:
        st.caption("No ML model active. Train REEM in the ML Lab; RiskBridge remains fully functional without ML.")
    st.caption("Security: the public app never deserializes user-uploaded pickle/joblib models.")

mode = st.radio(
    "What would you like to do?",
    [
        "🔎 Quick CVE Analysis",
        "🏢 Organization Analysis",
        "⚡ Zero-Day Asset Analysis",
        "🤖 ML Lab",
        "📊 Demo",
    ],
    horizontal=True,
)

config = default_config()

if mode == "🔎 Quick CVE Analysis":
    st.header("Quick CVE Analysis")
    st.write("Enter one or more CVE IDs. RiskBridge retrieves NVD, FIRST EPSS (including recent velocity), and CISA KEV, then combines that intelligence with the asset context you provide.")
    cve_text = st.text_area("CVE IDs", placeholder="CVE-2024-3094\nCVE-2021-44228\nCVE-2023-44487", height=130)
    remediation_hours = st.number_input("Estimated remediation effort per CVE (hours)", min_value=0.1, value=2.0, step=0.5)

    with st.expander("Asset, business, applicability, exposure, controls and preparedness", expanded=True):
        asset = asset_context_form("quick")

    if st.button("Analyze CVEs", type="primary", use_container_width=True):
        cves, invalid = parse_cves(cve_text)
        if invalid:
            st.error("Invalid CVE IDs: " + ", ".join(invalid))
        elif not cves:
            st.warning("Enter at least one CVE ID, for example CVE-2024-3094.")
        else:
            findings = pd.DataFrame([
                {
                    "finding_id": f"QUICK-{i:03d}",
                    "asset_id": asset["asset_id"],
                    "cve_id": cid,
                    "product": asset.get("asset_product") or "",
                    "installed_version": asset.get("asset_version") or "",
                    "remediation_hours": float(remediation_hours),
                }
                for i, cid in enumerate(cves, start=1)
            ])
            assets = pd.DataFrame([asset])
            with st.spinner("Retrieving NVD, EPSS history, CISA KEV and building RiskBridge decisions..."):
                scored, zero_day = run_analysis(
                    findings,
                    assets,
                    config,
                    live=True,
                    include_epss_history=True,
                    ml_bundle=ml_bundle,
                )
            render_scored_results(scored, zero_day, config, assets=assets, ml_bundle=ml_bundle)

elif mode == "🏢 Organization Analysis":
    st.header("Organization Analysis")
    st.write("Upload normalized findings and asset inventory. Relationships and scanner/vendor scores are optional enhancement layers.")
    c1, c2 = st.columns(2)
    with c1:
        findings_upload = st.file_uploader("Findings CSV", type="csv")
        relationships_upload = st.file_uploader("Relationships CSV (optional: from_asset,to_asset,relationship)", type="csv")
    with c2:
        assets_upload = st.file_uploader("Asset inventory CSV", type="csv")
        vendor_scores_upload = st.file_uploader("Vendor/scanner scores CSV (optional: cve_id,vendor,vendor_score,scale_max)", type="csv")
    config_upload = st.file_uploader("Policy / scoring YAML (optional)", type=["yaml", "yml"])
    live = st.toggle("Live NVD + EPSS + CISA KEV enrichment", value=True)
    history = st.toggle("Fetch 30-day EPSS history for up to 12 unique CVEs", value=False)
    use_demo_if_missing = st.checkbox("Use included demo data if files are not uploaded", value=False)

    if st.button("Run organization analysis", type="primary", use_container_width=True):
        if (findings_upload is None or assets_upload is None) and not use_demo_if_missing:
            st.warning("Upload both Findings and Assets CSV files, or enable the demo-data option.")
        else:
            findings = read_uploaded_csv(findings_upload, ROOT / "examples/findings.csv", load_findings)
            assets = read_uploaded_csv(assets_upload, ROOT / "examples/assets.csv", load_assets)
            org_config = load_config_upload(config_upload)
            relationships = uploaded_csv(relationships_upload)
            vendor_scores = uploaded_csv(vendor_scores_upload)
            with st.spinner("Analyzing organization data..."):
                scored, zero_day = run_analysis(
                    findings,
                    assets,
                    org_config,
                    live=live,
                    include_epss_history=history,
                    ml_bundle=ml_bundle,
                )
            render_scored_results(
                scored,
                zero_day,
                org_config,
                assets=assets,
                relationships=relationships,
                vendor_scores=vendor_scores,
                ml_bundle=ml_bundle,
            )

elif mode == "⚡ Zero-Day Asset Analysis":
    st.header("Pre-CVE Zero-Day Exposure & Preparedness")
    st.write("No CVE is required. Describe an asset to measure exposure to an unknown future vulnerability and how prepared the organization is to contain and recover from it.")
    asset = asset_context_form("zeroday")
    if st.button("Calculate pre-CVE exposure", type="primary", use_container_width=True):
        result = {**asset, **zero_day_exposure(pd.Series(asset), config)}
        zero_day_df = pd.DataFrame([result])
        score = result["zero_day_exposure_score"]
        rating = result["zero_day_exposure_rating"]
        st.success(f"Pre-CVE Exposure: {score:.1f}/100 — {rating}")
        prep = result.get("zero_day_preparedness_score")
        if prep is not None:
            st.info(f"Zero-Day Preparedness: {prep:.1f}/100 — {result.get('zero_day_preparedness_rating')}")
        render_zero_day_results(zero_day_df)

elif mode == "🤖 ML Lab":
    st.header("RiskBridge ML Lab — REEM")
    st.write("Train a real RiskBridge Emerging Exploitation Model on point-in-time labeled historical observations. The ML result is a threat signal, not the final business-risk decision.")
    st.warning("Avoid data leakage: historical rows must contain only information that was available on observation_date. Do not backfill later KEV status or later EPSS values into earlier observations.")

    with st.expander("Training CSV schema"):
        st.code(
            "observation_date,exploited_within_30d,cve_id,published,cvss_score,cvss_vector,cwe,epss,epss_percentile,epss_delta_7d,epss_delta_30d",
            language="text",
        )
        st.write("Minimum 30 rows; both 0 and 1 labels are required. A chronological 80/20 holdout is used instead of a random split.")

    training_upload = st.file_uploader("Historical ML training CSV", type="csv")
    if training_upload is not None:
        train_df = pd.read_csv(training_upload)
        st.write(f"Rows: {len(train_df)}")
        st.dataframe(train_df.head(20), use_container_width=True, hide_index=True)
        if st.button("Train REEM", type="primary"):
            try:
                bundle, metrics = train_exploitation_model(train_df)
                st.session_state["reem_bundle"] = bundle
                st.session_state["reem_metrics"] = metrics
                st.success("REEM trained. The model is now available to other RiskBridge modes in this browser session.")
            except Exception as exc:
                st.error(f"Training failed: {exc}")

    if st.session_state.get("reem_bundle"):
        bundle = st.session_state["reem_bundle"]
        metrics = bundle.get("metadata", {}).get("metrics", {})
        st.subheader("Held-out evaluation")
        st.dataframe(pd.DataFrame([metrics]), use_container_width=True, hide_index=True)
        st.download_button(
            "Download trained REEM model",
            data=model_to_bytes(bundle),
            file_name="riskbridge_reem.joblib",
            mime="application/octet-stream",
        )
        st.caption("PR-AUC and Brier score matter more than raw accuracy for an imbalanced exploitation-prediction problem.")

        if training_upload is not None and "riskbridge_score" in train_df.columns:
            try:
                validation = compare_rankings(train_df)
                st.subheader("Ranking comparison")
                st.dataframe(validation, use_container_width=True, hide_index=True)
            except Exception as exc:
                st.caption(f"Ranking comparison unavailable: {exc}")

else:
    st.header("RiskBridge Demo")
    st.write("Explore the platform using the included demonstration environment. Demo business context is illustrative; live threat intelligence can be refreshed separately.")
    live_demo = st.toggle("Refresh demo with live NVD + EPSS + CISA KEV intelligence", value=False)
    history_demo = st.toggle("Include EPSS history", value=False)
    if st.button("Run Demo", type="primary", use_container_width=True):
        findings = load_findings(ROOT / "examples/findings.csv")
        assets = load_assets(ROOT / "examples/assets.csv")
        with st.spinner("Running RiskBridge demo..."):
            scored, zero_day = run_analysis(
                findings,
                assets,
                config,
                live=live_demo,
                include_epss_history=history_demo,
                ml_bundle=ml_bundle,
            )
        render_scored_results(scored, zero_day, config, assets=assets, ml_bundle=ml_bundle)

st.divider()
st.caption(
    "RiskBridge is decision support. NVD applicability and vendor advisories should be verified before change execution. "
    "EPSS estimates exploitation likelihood for published CVEs; KEV records known exploitation; pre-CVE exposure is not zero-day prediction; "
    "and an ML signal is never allowed to replace business context or human accountability."
)

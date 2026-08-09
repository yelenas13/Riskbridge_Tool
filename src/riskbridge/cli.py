from __future__ import annotations

import argparse
from pathlib import Path

from .connectors import load_assets, load_findings
from .pipeline import run_analysis
from .reporting import export_outputs
from .utils import load_yaml


def _run(args: argparse.Namespace) -> None:
    config = load_yaml(args.config)
    findings = load_findings(args.findings)
    assets = load_assets(args.assets)
    scored, zero_day = run_analysis(findings, assets, config, live=args.live)
    weekly_hours = config.get("organization", {}).get("weekly_patch_capacity_hours")
    outputs = export_outputs(scored, zero_day, args.output, weekly_hours=weekly_hours)

    print(f"RiskBridge analyzed {len(scored)} findings across {assets['asset_id'].nunique()} assets.")
    if not scored.empty:
        print(scored[["cve_id", "hostname", "riskbridge_score", "priority", "confidence"]].head(10).to_string(index=False))
    print("\nOutputs:")
    for name, path in outputs.items():
        print(f"  {name}: {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="riskbridge", description="RiskBridge vulnerability prioritization")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze normalized findings and asset context")
    analyze.add_argument("--findings", required=True)
    analyze.add_argument("--assets", required=True)
    analyze.add_argument("--config", default="config/default.yaml")
    analyze.add_argument("--output", default="output")
    analyze.add_argument("--live", action="store_true", help="Enrich from NVD, FIRST EPSS, and CISA KEV")
    analyze.set_defaults(func=_run)

    demo = sub.add_parser("demo", help="Run the included example dataset")
    demo.add_argument("--config", default="config/default.yaml")
    demo.add_argument("--output", default="output")
    demo.add_argument("--live", action="store_true")
    demo.set_defaults(
        func=_run,
        findings="examples/findings.csv",
        assets="examples/assets.csv",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

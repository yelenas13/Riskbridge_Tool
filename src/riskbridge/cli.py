from __future__ import annotations

import argparse
from pathlib import Path
import pandas as pd

from .connectors import load_assets, load_findings
from .ml import load_model, save_model, train_exploitation_model
from .pipeline import run_analysis
from .reporting import export_outputs
from .utils import load_yaml


def _run(args: argparse.Namespace) -> None:
    config = load_yaml(args.config)
    findings = load_findings(args.findings)
    assets = load_assets(args.assets)
    ml_bundle = load_model(args.ml_model) if getattr(args, "ml_model", None) else None
    scored, zero_day = run_analysis(
        findings,
        assets,
        config,
        live=args.live,
        include_epss_history=getattr(args, "history", False),
        ml_bundle=ml_bundle,
    )
    weekly_hours = config.get("organization", {}).get("weekly_patch_capacity_hours")
    outputs = export_outputs(scored, zero_day, args.output, weekly_hours=weekly_hours)

    print(f"RiskBridge v0.4 analyzed {len(scored)} findings across {assets['asset_id'].nunique()} assets.")
    if not scored.empty:
        cols = ["cve_id", "hostname", "applicability_status", "riskbridge_score", "priority", "confidence"]
        print(scored[[c for c in cols if c in scored.columns]].head(10).to_string(index=False))
    print("\nOutputs:")
    for name, path in outputs.items():
        print(f"  {name}: {path}")


def _train_ml(args: argparse.Namespace) -> None:
    data = pd.read_csv(args.training_csv)
    bundle, metrics = train_exploitation_model(data)
    save_model(bundle, args.output_model)
    print(f"Saved REEM model: {args.output_model}")
    print(pd.DataFrame([metrics]).to_string(index=False))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="riskbridge", description="RiskBridge cyber-risk decision engine")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze normalized findings and asset context")
    analyze.add_argument("--findings", required=True)
    analyze.add_argument("--assets", required=True)
    analyze.add_argument("--config", default="config/default.yaml")
    analyze.add_argument("--output", default="output")
    analyze.add_argument("--live", action="store_true", help="Enrich from NVD, FIRST EPSS, and CISA KEV")
    analyze.add_argument("--history", action="store_true", help="Fetch FIRST 30-day EPSS history for a small analysis set")
    analyze.add_argument("--ml-model", help="Optional trained REEM .joblib model")
    analyze.set_defaults(func=_run)

    demo = sub.add_parser("demo", help="Run the included example dataset")
    demo.add_argument("--config", default="config/default.yaml")
    demo.add_argument("--output", default="output")
    demo.add_argument("--live", action="store_true")
    demo.add_argument("--history", action="store_true")
    demo.add_argument("--ml-model")
    demo.set_defaults(func=_run, findings="examples/findings.csv", assets="examples/assets.csv")

    train = sub.add_parser("ml-train", help="Train the RiskBridge Emerging Exploitation Model (REEM)")
    train.add_argument("--training-csv", required=True)
    train.add_argument("--output-model", default="models/reem.joblib")
    train.set_defaults(func=_train_ml)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

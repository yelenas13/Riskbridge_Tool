# Riskbridge_tool_Tool

**Explainable, business-aligned vulnerability prioritization and pre-CVE zero-day exposure modeling.**

Riskbridge_tool sits above vulnerability scanners and public threat-intelligence feeds. It combines technical severity,
exploitation likelihood, asset/business context, exposure, and compensating controls to answer a practical question:

> **What should this organization fix first, why, and where is it exposed even before the next CVE is known?**

## What is different in this version

Riskbridge_tool v0.3 replaces the original Colab prototype with a maintainable Python package.

- No random/synthetic security values are used as fallback data.
- Missing intelligence reduces decision confidence instead of being silently fabricated.
- Known-CVE prioritization and pre-CVE zero-day exposure are separate models.
- The old "zero-day-like" CVE heuristic is reframed as an **Emerging Vulnerability Score** because EPSS/CVSS require a disclosed CVE.
- The **Zero-Day Exposure Surface** model is asset-based and does not require a CVE, CVSS, EPSS, or KEV.
- Scanner integrations are optional adapters. Generic CSV works today; Qualys/Tenable/Defender/Rapid7 can be added later without changing the scoring engine.

## Data sources

When `--live` is enabled, Riskbridge_tool enriches CVEs from:

- NIST NVD CVE API 2.0: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- FIRST EPSS API: `https://api.first.org/data/v1/epss`
- CISA Known Exploited Vulnerabilities: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

The NVD implementation uses the current `cveIds` batch parameter rather than the deprecated single-CVE `cveId` parameter.
EPSS probability and percentile are both used as threat signals.

## Risk models

### 1. Known vulnerability score

Riskbridge_tool calculates independent dimensions from 0-100:

- **Technical severity** — CVSS
- **Threat likelihood** — EPSS probability, EPSS percentile, CISA KEV
- **Business impact** — criticality, data sensitivity, revenue/safety impact, production context
- **Exposure** — internet exposure, privileges, public API/remote access, network reachability, open services
- **Control effectiveness** — segmentation, EDR, WAF, least privilege, monitoring

Default base weighting:

```text
Technical 20% + Threat 30% + Business 30% + Exposure 20%
```

Controls can reduce the resulting score, but only up to a configurable cap. This prevents a compensating control from
mathematically erasing severe exposure.

### 2. Emerging Vulnerability Score

For disclosed CVEs, Riskbridge_tool separately measures emerging risk using:

- EPSS
- EPSS percentile
- CVSS
- publication recency

This is intentionally **not** called zero-day prediction.

### 3. Zero-Day Exposure Surface

The pre-CVE model asks where an unknown vulnerability could create the largest enterprise exposure.

It evaluates:

- Attack surface
- Privilege and network reachability
- Unsupported/aging software and third-party exposure
- Business impact
- Control weakness

It does **not** use CVSS, EPSS, KEV, or a CVE ID.

## Dashboard

The Streamlit dashboard contains:

- Executive metrics
- Risk-dimension radar chart
- Priority distribution
- EPSS vs Riskbridge_tool scatter view
- Prioritized vulnerability table
- Highest-exposure radial gauge
- Zero-day asset radar chart
- Zero-Day Exposure Surface Matrix
- Patch bundle / risk-per-hour optimizer
- Decision-confidence view

## Repository structure

```text
Riskbridge_tool/
├── app.py
├── pyproject.toml
├── requirements.txt
├── README.md
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
├── config/
│   └── default.yaml
├── docs/
│   ├── DATA_SCHEMA.md
│   └── INTEGRATIONS.md
├── examples/
│   ├── findings.csv
│   └── assets.csv
├── src/Riskbridge_tool/
│   ├── __init__.py
│   ├── cli.py
│   ├── intelligence.py
│   ├── optimizer.py
│   ├── pipeline.py
│   ├── policy.py
│   ├── reporting.py
│   ├── scoring.py
│   ├── utils.py
│   ├── zero_day.py
│   └── connectors/
│       ├── __init__.py
│       ├── generic_csv.py
│       └── vendor_template.py
├── tests/
│   ├── test_optimizer.py
│   ├── test_scoring.py
│   └── test_zero_day.py
└── .github/workflows/
    └── tests.yml
```

## Installation

### Windows PowerShell

```powershell
git clone https://github.com/YOUR-USERNAME/Riskbridge_tool.git
cd Riskbridge_tool
python -m venv riskenv
.\riskenv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e .
```

### macOS / Linux

```bash
git clone https://github.com/YOUR-USERNAME/Riskbridge_tool.git
cd Riskbridge_tool
python -m venv riskenv
source riskenv/bin/activate
python -m pip install --upgrade pip
pip install -e .
```

## Run the demo

Offline, using the included example data:

```bash
Riskbridge_tool demo
```

With live NVD + EPSS + KEV enrichment:

```bash
Riskbridge_tool demo --live
```

Outputs are written to `output/`:

- `prioritized_vulnerabilities.csv`
- `zero_day_exposure.csv`
- `remediation_optimizer.csv`
- `Riskbridge_tool_report.xlsx`
- `Riskbridge_tool_summary.json`

## Run the graphical dashboard

```bash
streamlit run app.py
```

Then open the local URL Streamlit prints in your terminal.

## Analyze organization data

```bash
Riskbridge_tool analyze \
  --findings my_findings.csv \
  --assets my_assets.csv \
  --config config/default.yaml \
  --output output \
  --live
```

Without internet enrichment:

```bash
Riskbridge_tool analyze \
  --findings my_findings.csv \
  --assets my_assets.csv \
  --output output
```

## Scanner strategy

Riskbridge_tool is intentionally vendor-neutral:

```text
Qualys ─────┐
Tenable ────┤
Defender ───┼──> Normalized Riskbridge_tool finding schema ──> scoring engine
Rapid7 ─────┤
CSV/JSON ───┘
```

A scanner should find vulnerabilities. Riskbridge_tool should determine how much the organization should care and why.

See `docs/INTEGRATIONS.md` before implementing a scanner connector.

## Compliance note

Riskbridge_tool maps findings to relevant control families for context, but the remediation deadlines in `config/default.yaml`
are **organization policy**, not universal deadlines imposed by NIST, ISO, CIS, or every PCI environment. Organizations
must configure their own approved remediation and exception policy.

## Important limitations

- Riskbridge_tool is decision support, not a guarantee that exploitation will or will not occur.
- EPSS estimates exploitation probability for published CVEs; it is not a business-risk score.
- KEV confirms known exploitation but absence from KEV does not mean a vulnerability is safe.
- The pre-CVE zero-day model measures **exposure**, not the probability that a particular unknown vulnerability exists.
- Financial loss should not be invented. Riskbridge_tool v0.3 optimizes risk points per remediation hour unless an organization
  later provides defensible cost/loss data.

## Tests

```bash
pytest -q
```

## License

MIT

## Installation fallback for restricted environments

If editable installation is blocked by an internal package mirror, install the dependencies first and run directly from `src`:

```bash
pip install -r requirements.txt
```

macOS/Linux:

```bash
PYTHONPATH=src python -m Riskbridge_tool.cli demo
```

Windows PowerShell:

```powershell
$env:PYTHONPATH="src"
python -m Riskbridge_tool.cli demo
```

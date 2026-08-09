# RiskBridge Model Specification

RiskBridge separates **known-vulnerability risk**, **post-disclosure emerging risk**, and **pre-CVE zero-day exposure**.
This separation prevents CVE-dependent signals from being misrepresented as zero-day prediction.

## 1. Known-vulnerability decision score

Each available dimension is normalized to 0-100.

### Technical severity

```text
Technical = CVSS base score × 10
```

### Threat likelihood

Default weighting among available signals:

```text
Threat = 50% EPSS probability
       + 20% EPSS percentile
       + 30% CISA KEV status
```

Signals that are unavailable are not replaced with random values. The component is re-weighted across available signals,
and decision confidence is reduced.

### Business impact

Default inputs:

- Asset criticality
- Data sensitivity
- Revenue impact
- Safety impact
- Environment (production/staging/test/development)

### Exposure

Default inputs:

- Internet exposure
- Privileged position
- Public API
- Remote access
- Network reachability
- Open-service count

### Control effectiveness

Default inputs:

- Segmentation
- EDR
- WAF
- Least privilege
- Monitoring

### Base score

```text
Base = 20% Technical
     + 30% Threat
     + 30% Business
     + 20% Exposure
```

### Residual score

Controls reduce the base score according to a configurable mitigation cap:

```text
Residual = Base × (1 - ControlEffectiveness × ControlMitigationCap)
```

With the default `control_mitigation_cap = 0.35`, even perfect controls can reduce the calculated base score by no more
than 35%. This prevents compensating controls from mathematically erasing material risk.

### Priority

Default score bands:

```text
P0: score >= 85
P1: score >= 70
P2: score >= 50
P3: score < 50
```

Threat/context overrides can elevate a finding. For example, a KEV vulnerability with high business impact or exposure
can be elevated to P0 even if the residual numeric score is below 85.

## 2. Emerging Vulnerability Score (EVS)

This is a post-disclosure signal, not zero-day prediction.

```text
EVS = 40% EPSS
    + 20% EPSS percentile
    + 20% CVSS
    + 20% publication recency
```

It is intended to highlight newly disclosed vulnerabilities that may deserve attention before they appear in KEV.

## 3. Zero-Day Exposure Surface Score

This model requires no CVE, CVSS, EPSS, or KEV information.

Default dimensions:

```text
25% Attack Surface
20% Privilege & Reachability
20% Software Exposure
25% Business Impact
10% Control Weakness
```

Attack-surface inputs include internet exposure, public APIs, remote access, open services, and third-party exposure.
Software-exposure inputs include unsupported software, technology age, and third-party exposure.

The score answers:

> If an unknown exploitable flaw appeared in this asset or technology tomorrow, how much exposure would the organization have?

It does **not** estimate the probability that a zero-day vulnerability exists.

## 4. Decision confidence

RiskBridge reports data completeness alongside the score. Current confidence checks include:

- CVSS available
- EPSS available
- KEV status available
- Asset criticality available
- Exposure context available
- Control context available

Missing data is shown in `data_gaps`.

## 5. Remediation optimizer

The optimizer uses:

```text
Risk points removed / estimated remediation hours
```

It intentionally avoids invented dollar loss values. Organizations can add financial modeling later only when they have
credible asset-value, outage, labor, and loss assumptions.

## Governance

Weights and thresholds are policy choices, not universal scientific constants. Organizations should validate changes
against historical incidents, red-team findings, exploitation outcomes, patch capacity, and risk appetite before production use.

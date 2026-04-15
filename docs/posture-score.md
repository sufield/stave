# Posture Score (0-100)

A single, auditable security posture metric computed from assessment output.

## Why a Score?

Violation counts increase when new controls are added or new assets are
observed, independent of actual posture improvement. A normalized 0-100
score weighted by severity-adjusted risk exposure stays stable during
catalog expansion and moves only when actual misconfigurations are
introduced or remediated.

## Score Formula

The posture score is a weighted combination of four dimensions. Each
dimension produces a sub-score from 0.0 to 1.0. The final score is the
weighted sum multiplied by 100, rounded to one decimal place.

```
PostureScore = 100 * (
    w_severity   * SeverityScore   +
    w_sla        * SLAScore        +
    w_chain      * ChainScore      +
    w_coverage   * CoverageScore
)

Default weights:
  w_severity  = 0.45   (45%)
  w_sla       = 0.25   (25%)
  w_chain     = 0.20   (20%)
  w_coverage  = 0.10   (10%)
```

### SeverityScore (0.0-1.0)

Measures the severity-weighted proportion of evaluations that pass.

```
SeverityWeight:
  critical  = 10.0
  high      = 4.0
  medium    = 2.0
  low       = 1.0

MaxRiskExposure = sum(SeverityWeight[sev] for ALL evaluations)
ActualExposure  = sum(SeverityWeight[sev] for FAILING evaluations)

SeverityScore = 1.0 - (ActualExposure / MaxRiskExposure)
```

### SLAScore (0.0-1.0)

Measures the proportion of findings remediated within their SLA deadline.

```
SLAScore = 1.0 - (FindingsBreached / FindingsWithSLA)
```

When no SLA profile is configured, SLAScore = 1.0 (not penalized).

### ChainScore (0.0-1.0)

Measures the absence of active compound chains, weighted by chain severity.

```
ChainWeight:
  critical = 10.0
  high     = 4.0
  medium   = 2.0

ChainScore = 1.0 - (ActiveChainWeight / MaxChainWeight)
```

### CoverageScore (0.0-1.0)

Measures framework compliance coverage breadth. Averaged across all
active frameworks from the `--compliance` flag.

```
CoverageScore = avg(ReadinessPercent for each matching framework) / 100
```

When no compliance profile is configured, CoverageScore = 1.0.

## Rubric

| Range   | Band            | Description                                         |
|---------|-----------------|-----------------------------------------------------|
| 90-100  | STRONG          | No critical findings. No SLA breaches. No chains.   |
| 75-89   | ADEQUATE        | No critical SLA breaches. <2 active chains.         |
| 60-74   | NEEDS ATTENTION | Critical findings or SLA breach rate >10%.          |
| 40-59   | AT RISK         | Multiple critical SLA breaches. Active chains.      |
| 0-39    | CRITICAL        | Widespread SLA breaches. Immediate action required. |

## Catalog Expansion

When new controls are added to the catalog, `MaxRiskExposure` grows.

**If all new controls pass:** `ActualExposure` stays the same while
`MaxRiskExposure` increases. SeverityScore stays stable or improves.
The overall posture score does not decrease.

**If new controls reveal failures:** `ActualExposure` grows and the
score decreases. This is the correct response -- the posture was
always this bad, Stave just was not measuring it.

### Example

An organization has 100 controls, all passing. Score: 100.

They add 30 Cisco IOS controls to the catalog. All 30 fail because
the network equipment was never configured to these standards.

- Before: MaxRiskExposure = 200, ActualExposure = 0, SeverityScore = 1.0
- After:  MaxRiskExposure = 260, ActualExposure = 60, SeverityScore = 0.77

The score drops from 100 to ~79.3. This correctly reflects that the
organization's posture was worse than previously measured. As they
remediate the Cisco controls, the score recovers.

## Usage

```bash
# Current score
stave score --output assessment.json

# Score with compliance coverage
stave score --output assessment.json --compliance hipaa

# Score trend over history
stave score --history ./assessments/ --compliance hipaa

# OpenMetrics for Prometheus
stave score --output assessment.json --format openmetrics

# Custom weights
stave score --output assessment.json --weights severity=0.60,sla=0.20,chain=0.15,coverage=0.05
```

## OpenMetrics Integration

The `stave_posture_score` gauge is emitted by both `stave score` and
`stave trend` in OpenMetrics format, enabling Prometheus/Grafana
dashboards in air-gapped SOC environments.

## Determinism

The score formula is published and deterministic. Given the same
`out.v0.1.json` input and the same weights, the score is identical.
An auditor can verify any historical score from the stored assessment
output that produced it.

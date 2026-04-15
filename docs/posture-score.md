# Posture Score (0–100)

The `stave score` command produces a single auditable security posture metric
that survives catalog growth. This document explains the formula, each component,
and the catalog expansion property that makes the score a durable KPI.

## Formula

```
PostureScore = 100 × (
    w_severity   × SeverityScore   +
    w_sla        × SLAScore        +
    w_chain      × ChainScore      +
    w_coverage   × CoverageScore
)

Default weights:
  w_severity  = 0.45   (45%) — severity distribution is the primary signal
  w_sla       = 0.25   (25%) — SLA compliance measures response discipline
  w_chain     = 0.20   (20%) — active chains indicate compound exposure
  w_coverage  = 0.10   (10%) — framework coverage measures breadth
```

The final score is rounded to one decimal place for display and stored as
`float64` internally.

## SeverityScore (0.0–1.0)

Measures the severity-weighted proportion of findings that pass.

```
SeverityWeight:
  critical  = 10.0
  high      = 4.0
  medium    = 2.0
  low       = 1.0

MaxRiskExposure = sum(SeverityWeight[sev] for each finding in all findings)
ActualExposure  = sum(SeverityWeight[sev] for each FAILING finding)

SeverityScore = 1.0 - (ActualExposure / MaxRiskExposure)
```

**Monotone property:** fixing any finding increases `SeverityScore`. Adding
new controls to the catalog that all pass does not decrease `SeverityScore`
(numerator stays the same, denominator grows, score stays stable or improves).

## SLAScore (0.0–1.0)

Measures the proportion of findings remediated within their SLA deadline.

```
FindingsWithSLA  = findings that have an applicable SLA deadline
FindingsBreached = findings where dwell_time > sla_deadline_hours

SLAScore = 1.0 - (FindingsBreached / FindingsWithSLA)
```

If no SLA profile is configured: `SLAScore = 1.0` (not penalized for not
configuring SLA enforcement).

## ChainScore (0.0–1.0)

Measures the absence of active compound attack chains, weighted by chain
compound severity.

```
MaxChainWeight    = sum(ChainWeight[sev] for all chain definitions)
ActiveChainWeight = sum(ChainWeight[sev] for each ACTIVE chain)

ChainScore = 1.0 - (ActiveChainWeight / MaxChainWeight)
```

Zero active chains → `ChainScore = 1.0`.

## CoverageScore (0.0–1.0)

Measures compliance framework coverage breadth.

```
If no compliance profile configured:
  CoverageScore = 1.0 (not penalized)

If compliance profile configured:
  CoverageScore = RequirementsSatisfied / TotalRequirements
```

## Score Rubric

| Range  | Label           | Meaning |
|--------|-----------------|---------|
| 90–100 | STRONG          | No critical findings failing. No SLA breaches. No active chains. |
| 75–89  | ADEQUATE        | No critical SLA breaches. Fewer than 2 active chains. |
| 60–74  | NEEDS ATTENTION | Critical findings present or SLA breach rate > 10%. |
| 40–59  | AT RISK         | Multiple critical findings breaching SLA. Active chains. |
| 0–39   | CRITICAL        | Widespread critical SLA breaches. Immediate remediation required. |

## The Catalog Expansion Property

This is the most important property of the score for long-term leadership
reporting.

**Problem:** When new controls are added to the catalog, the violation
*count* increases even when no new problems exist — leadership cannot use raw
violation counts as a KPI.

**How Stave handles this:**

When 30 new Cisco IOS controls are added to the catalog and all pass, the
`MaxRiskExposure` denominator grows (more controls = more risk surface
measured), but `ActualExposure` stays the same (no new violations). The
`SeverityScore` stays stable or improves.

When 30 new controls are added and they all fail (revealing previously
unmeasured problems), `SeverityScore` decreases — **correctly reflecting that
posture was always this bad; Stave just was not measuring it.** This is the
correct behavior: the score should reflect the true state of the environment,
not the breadth of catalog coverage.

**Example:**

| Scenario | MaxRiskExposure | ActualExposure | SeverityScore |
|----------|----------------|----------------|---------------|
| Baseline: 100 findings, 10 failing (all high) | 400 | 40 | 0.90 |
| Add 30 new controls, all pass (high) | 520 | 40 | 0.923 ↑ |
| Add 30 new controls, all fail (high) | 520 | 160 | 0.692 ↓ |

In the third scenario, the score drop is correct — it reflects that 40 new
high-severity misconfigurations were present but unmeasured. This is Stave's
core identity applied to the metric layer: the score is honest about the
environment's true state.

## Usage

```bash
# Score from a single assessment
stave score --output ./out.v0.1.json

# Score with JSON output
stave score --output ./out.v0.1.json --format json

# Score with OpenMetrics output (for Prometheus)
stave score --output ./out.v0.1.json --format openmetrics

# Score trend over assessment history
stave score --history ./assessments/ --compliance hipaa

# Override weights
stave score --output ./out.v0.1.json \
  --weights severity=0.5,sla=0.3,chain=0.1,coverage=0.1
```

## OpenMetrics Gauges

| Metric | Description |
|--------|-------------|
| `stave_posture_score` | Overall score (0–100) |
| `stave_posture_score_severity_component` | Severity sub-score (0–1) |
| `stave_posture_score_sla_component` | SLA compliance sub-score (0–1) |
| `stave_posture_score_chain_component` | Chain activity sub-score (0–1) |
| `stave_posture_score_coverage_component` | Framework coverage sub-score (0–1) |
| `stave_posture_score_rubric_band` | Band (0=critical, 1=at_risk, 2=needs_attention, 3=adequate, 4=strong) |

The `stave_posture_score` gauge is also emitted by `stave trend --format openmetrics`
so that trend and score share a single metrics endpoint.

## Integration with `stave apply`

When `stave apply --format json` runs, the assessment output includes a partial
posture score (severity and chain components only — SLA and coverage require
external profile configuration):

```json
{
  "posture_score": 74.3,
  "posture_score_rubric": "needs_attention",
  "posture_score_partial": true
}
```

The `posture_score_partial: true` flag indicates that the SLA and coverage
components were not configured for this run.

## Integration with `stave collect`

Each evidence archive run includes the posture score in `run-metadata.json`:

```json
{
  "run_id": "2026-01-15T14-30-00Z",
  "posture_score": 81.2,
  "posture_score_rubric": "adequate"
}
```

This enables historical posture score tracking across collection runs.

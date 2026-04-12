# Blast Radius

Blast radius measures how far damage spreads when a control fails. A
disabled S3 access log is a local problem. A disabled CloudTrail is an
account-wide blindness that makes every other violation invisible. Stave
models this difference through scoped multipliers that adjust compound
risk scores based on the real impact of each control failure.

## The concept

Not all control failures are equal. Some controls, when disabled, degrade
the safety envelope of a single resource. Others degrade the safety
envelope of everything in the account. The blast radius system captures
this by attaching three properties to detection controls:

| Property | Values | Meaning |
|---|---|---|
| `type` | detection, prevention, recovery | What kind of protection this control provides |
| `scope` | account, network, resource | How far the damage spreads when this control fails |
| `multiplier` | 1.0 - 2.5+ | How much to inflate compound scores when this control co-fails |

## How it works

### 1. Controls declare their blast radius

Detection controls carry blast radius metadata in their `params`:

```yaml
# CloudTrail — account-scoped, maximum impact
id: CTL.CLOUDTRAIL.ENABLED.001
params:
  attack_stage: detection_evasion
  blast_radius:
    type: detection
    scope: account
    multiplier: 2.5
```

```yaml
# S3 access logging — resource-scoped, local impact
id: CTL.S3.LOG.001
params:
  attack_stage: detection_evasion
  blast_radius:
    type: detection
    scope: resource
    multiplier: 1.5
```

### 2. Scope attenuation adjusts the multiplier

When the chain engine computes compound scores, it attenuates the
multiplier based on scope. This prevents a single disabled S3 access
log from inflating scores across unrelated resources:

| Scope | Attenuation | Rationale |
|---|---|---|
| **account** | Full multiplier | Blinds everything — CloudTrail, GuardDuty, Config |
| **network** | 75% of excess above 1.0 | VPC Flow Logs affect resources in that VPC only |
| **resource** | 50% of excess above 1.0 | S3 logging affects only that bucket |

Example with a 2.5x declared multiplier:
- Account scope: effective = **2.5x**
- Network scope: effective = 1.0 + (2.5-1.0) × 0.75 = **2.125x**
- Resource scope: effective = 1.0 + (2.5-1.0) × 0.50 = **1.75x**

### 3. Multiplier feeds into compound scoring

The blast multiplier is the third factor in the compound risk formula:

```
Compound Score = Environmental × Chain Escalation × Blast Multiplier
```

Where:
- **Environmental** = base_impact × asset_sensitivity × exposure_vector
- **Chain escalation** = 1.0x (1 control), 1.8x (2 controls), 2.5x (3+)
- **Blast multiplier** = scope-adjusted multiplier from the highest-impact failing control

## Annotated controls

These 8 detection controls currently carry blast radius metadata:

| Control | Scope | Multiplier | What disabling it blinds |
|---|---|---|---|
| CTL.CLOUDTRAIL.ENABLED.001 | account | 2.5x | All API-level audit trail |
| CTL.GUARDDUTY.ENABLED.001 | account | 2.5x | Anomaly and threat detection |
| CTL.CONFIG.ENABLED.001 | account | 2.5x | Configuration change tracking |
| CTL.SECURITYHUB.ENABLED.001 | account | 2.5x | Findings aggregation across services |
| CTL.VPC.FLOWLOG.001 | network | 2.0x | Network traffic visibility in that VPC |
| CTL.S3.AUDIT.OBJECTLEVEL.001 | resource | 2.0x | Object-level access audit for that bucket |
| CTL.S3.LOG.001 | resource | 1.5x | Server access logging for that bucket |
| CTL.CLOUDWATCH.RETENTION.001 | account | 1.5x | Historical log availability for investigation |

## How to interpret the output

### JSON output

```json
{
  "chain_findings": [{
    "chain": "detection_blindness",
    "controls_failing": [
      "CTL.CLOUDTRAIL.ENABLED.001",
      "CTL.GUARDDUTY.ENABLED.001"
    ],
    "missing_safeguards": [
      "CTL.CONFIG.ENABLED.001",
      "CTL.VPC.FLOWLOG.001"
    ],
    "compound_score": 45.0,
    "severity": "CRITICAL",
    "attack_stages": ["detection_evasion"]
  }]
}
```

Reading this:
- **chain**: which safety chain has been breached
- **controls_failing**: the controls that are currently violated
- **missing_safeguards**: controls in the chain that are still intact — **fix any of these to weaken the chain**
- **compound_score**: risk score with blast multiplier applied
- **severity**: chain-level severity (CRITICAL when detection is blind)
- **attack_stages**: MITRE-aligned stages affected

### Text output

```
Compound Risk Chains
--------------------

  [CRITICAL] Chain: detection_blindness
  Detection controls disabled — all violations invisible.
  Failing:    CTL.CLOUDTRAIL.ENABLED.001, CTL.GUARDDUTY.ENABLED.001
  Fix any of: CTL.CONFIG.ENABLED.001, CTL.VPC.FLOWLOG.001
  Score:      45.0
  Stages:     detection_evasion

Attack Stage Summary
--------------------
  initial_access       PASS
  credential_access    PASS
  detection_evasion    CRITICAL
  resilience           PASS
```

The "Fix any of" line is the most actionable item in the report.
Enabling either Config or VPC Flow Logs would drop the chain below
its escalation threshold, breaking the compound finding.

## Adding blast radius to custom controls

Any control can declare blast radius in its params:

```yaml
params:
  attack_stage: detection_evasion
  blast_radius:
    type: detection       # detection | prevention | recovery
    scope: account        # account | network | resource
    multiplier: 2.5       # how much to inflate compound scores
```

Controls without blast_radius params default to multiplier 1.0 and
resource scope — they don't inflate compound scores.

### When to add blast radius

Add it when disabling the control makes other violations harder to
detect, prevent, or recover from:

| Type | When to use | Example |
|---|---|---|
| **detection** | Disabling blinds the audit trail | CloudTrail, GuardDuty, logging |
| **prevention** | Disabling removes a security barrier | Block Public Access, MFA |
| **recovery** | Disabling removes recovery capability | Backups, versioning, Object Lock |

### Choosing the right scope

| Scope | When to use | Example |
|---|---|---|
| **account** | Control affects the entire AWS account | CloudTrail, Config, GuardDuty |
| **network** | Control affects resources in one VPC | VPC Flow Logs, NACLs |
| **resource** | Control affects one specific resource | S3 bucket logging, RDS audit |

### Choosing the multiplier

| Multiplier | When to use |
|---|---|
| 1.0 | No blast radius effect (default) |
| 1.5 | Local detection gap, limited investigation impact |
| 2.0 | Significant detection or protection gap |
| 2.5+ | Account-wide blindness, total detection failure |

## Design principles

**Bounded, not multiplicative.** Chain escalation caps at 2.5x even
with 10 co-failing controls. A bucket that's public + unencrypted +
unlogged is catastrophically worse than public alone, but the marginal
risk has diminishing returns.

**Scope-proportional.** A resource-scoped detection gap doesn't inflate
account-wide scores. The math is proportional to the actual blast radius.

**Deterministic.** Given the same controls and chain definitions, the
same score is always produced. No probabilistic models, no black boxes.
The auditor can read the chain YAML, verify the multiplier table, and
reproduce the score by hand.

## Identity blast radius

Stave also models **identity blast radius** — how far damage spreads
when a credential is compromised. This is separate from control-level
blast radius:

| Type | What it measures | Documentation |
|---|---|---|
| Control blast radius | How disabling a control blinds the account | This page |
| Identity blast radius | How many resources a compromised role can reach | [Identity Blast Radius](identity-blast-radius.md) |

Three controls (CTL.IAM.IDENTITY.BLASTRADIUS.001-003) evaluate
pre-computed identity blast radius properties from the observation.
A fourth chain definition (`identity_blast_radius`) combines wide
reach with missing credential protections.

## Key files

| File | Purpose |
|---|---|
| `internal/core/controldef/definition.go` | BlastRadiusType(), BlastMultiplier(), BlastScope() accessors |
| `internal/core/evaluation/risk/chain_engine.go` | scopeAdjustedBlast(), DetectChains() |
| `internal/core/evaluation/risk/calculator.go` | Compound() scoring formula |
| `internal/adapters/output/text/finding_writer.go` | Text rendering of chain findings |
| `chains/*.yaml` | Built-in chain definitions |

# Risk Reasoning Engine

Stave's risk reasoning engine transforms individual findings into
compound risk assessments using three layers of scoring.

## Architecture

```
Assessor    → Observation  (CEL evaluator + snapshots)
RiskEngine  → Inference    (multipliers + chain engine)
Reporter    → Attestation  (structured reasoning output)
```

## Risk scoring layers

### Layer 1: Environmental

```
Environmental = base_impact × asset_sensitivity × exposure_vector
```

- `base_impact`: 0-100, from control `params.base_impact`
- `asset_sensitivity`: phi=3.0, production=2.0, internal=1.0, dev=0.5
- `exposure_vector`: public=2.0, cross_account=1.5, vpc=1.0

### Layer 2: Compound

```
Compound = environmental × chain_escalation × blast_multiplier
```

- `chain_escalation`: 1=1.0x, 2=1.8x, 3+=2.5x (bounded)
- `blast_multiplier`: from control `params.blast_radius.multiplier`

### Layer 3: Attack Stage Summary

Maps MITRE ATT&CK-aligned stages to worst severity:

- `initial_access` — public S3, open SGs, public RDS
- `credential_access` — MFA failures, key rotation
- `persistence` — IAM self-modification, break-glass
- `exfiltration` — encryption controls
- `detection_evasion` — CloudTrail, GuardDuty, Config
- `resilience` — backups, versioning, Object Lock

## Chain definitions

Chains live in `chains/*.yaml`:

```yaml
id: public_phi_exposure
description: PHI data reachable from public internet
controls:
  - CTL.S3.PUBLIC.001
  - CTL.S3.ENCRYPT.001
  - CTL.S3.LOG.001
  - CTL.CLOUDTRAIL.DATAREAD.001
escalation_threshold: 2
compound_severity: critical
```

Built-in chains: `public_phi_exposure`, `root_compromise_path`,
`detection_blindness`, `identity_blast_radius`,
`unauthenticated_data_path`.

## Control risk metadata

Controls opt into risk scoring via `params`:

```yaml
params:
  base_impact: 10
  attack_stage: initial_access
  chain_ids:
    - public_phi_exposure
  blast_radius:
    type: detection
    scope: account
    multiplier: 2.5
```

Controls without risk params default to safe values (0, 1.0).

## Exposure ranking (Silent Killer Finder)

The risk engine ranks all findings by exposure score to answer
"what to fix first?" The ranking identifies long-lived, high-impact
failures that persist undetected — the silent killers.

### Scoring formula

```
ExposureScore = BaseScore × DurationFactor × BlastMultiplier × ExposureMultiplier
```

| Factor | Source | Values |
|---|---|---|
| BaseScore | `params.base_impact` or severity fallback | 10-100 |
| DurationFactor | `Evidence.UnsafeDurationHours` stepped | 1.0 / 1.5 / 2.0 / 3.0 / 5.0 |
| BlastMultiplier | `params.blast_radius.multiplier` | 1.0-2.5 |
| ExposureMultiplier | `Exposure.PrincipalScope` | 1.0 (internal), 2.0 (public) |

Duration factor steps:

| Duration | Factor | Label |
|---|---|---|
| < 30 days | 1.0 | Recent |
| 30-89 days | 1.5 | Aging |
| 90-364 days | 2.0 | Stale |
| 365-1642 days | 3.0 | Long-lived |
| 1643+ days (4.5 years) | 5.0 | Silent killer |

Findings with `days_blind > 300` are flagged as silent killers.

### Output

Top 10 exposures are shown in text output. The full ranked list
appears in JSON as `top_exposures`:

```json
{
  "top_exposures": [
    {
      "finding_index": 0,
      "control_id": "CTL.S3.PUBLIC.001",
      "asset_id": "arn:aws:s3:::phi-records-prod",
      "exposure_score": 2500.0,
      "breakdown": {
        "base_score": 100,
        "duration_factor": 5.0,
        "blast_multiplier": 2.5,
        "exposure_multiplier": 2.0,
        "days_blind": 1826.0
      },
      "silent_killer": true
    }
  ]
}
```

Text output:

```
Top Exposures
-------------
   1  2500.0   1826d  CTL.S3.PUBLIC.001          s3:phi-records-prod
      SILENT KILLER  base=100 × duration=5.0 × blast=2.5 × exposure=2.0
```

The ranking is deterministic: same inputs always produce the same
order. Ties are broken by ControlID then AssetID.

## Output

```json
{
  "chain_findings": [{
    "chain": "public_phi_exposure",
    "controls_failing": ["CTL.S3.PUBLIC.001", "CTL.S3.ENCRYPT.001"],
    "compound_score": 126.0,
    "severity": "CRITICAL",
    "narrative": "PHI data reachable from public internet..."
  }],
  "attack_stage_summary": {
    "initial_access": "CRITICAL",
    "credential_access": "PASS",
    "detection_evasion": "HIGH",
    "resilience": "PASS"
  }
}
```

## Key files

| File | Purpose |
|---|---|
| `internal/core/controldef/chain.go` | ChainDefinition type |
| `internal/core/evaluation/risk/calculator.go` | Environmental, Compound, ChainEscalation |
| `internal/core/evaluation/risk/chain_engine.go` | DetectChains |
| `internal/core/evaluation/risk/attack_stage.go` | BuildAttackStageSummary |
| `internal/core/evaluation/risk/exposure_rank.go` | ExposureRank, DurationFactor, RankExposures |
| `internal/app/eval/workflow.go` | Pipeline wiring (enrichWithRiskReasoning) |
| `chains/*.yaml` | Built-in chain definitions |

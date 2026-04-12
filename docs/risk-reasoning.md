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
`detection_blindness`.

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
| `internal/app/eval/workflow.go` | Pipeline wiring (enrichWithRiskReasoning) |
| `chains/*.yaml` | Built-in chain definitions |

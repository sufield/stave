# templates/

Built-in evaluation templates that bundle a use case into a parameterized runbook. Each template defines what to evaluate, how to scope it, and what output to produce. Templates are embedded into the `stave` binary via `embed.go`.

## Available Templates

| Template | Job |
|----------|-----|
| `critical-findings` | Surface critical and high severity findings across whatever services are in the snapshot |
| `bucket-hijacking-assessment` | Assess bucket hijacking exposure across all 42 router-to-S3 destination binding types |
| `breach-reconstruction` | Reconstruct what an attacker could reach at a specific point in time |
| `independent-audit` | Produce audit-grade evidence package with deterministic reproduction |
| `m-and-a-diligence` | Evaluate acquisition target's cloud security posture without credentials |

## Template Structure

Each template directory contains:

```
<name>/
├── template.yaml           Template definition (parameters, scope, runbook)
└── fixtures/
    ├── snapshot.json        Test fixture (obs.v0.1 observation)
    └── expected.jsonl       Expected findings for fixture validation
```

## Template Format

```yaml
apiVersion: stave/v1
kind: Template
metadata:
  name: <template-name>
  description: <one-line description>
  job: <what the template does for the user>
  version: "1.0.0"

recommend_when:
  predicate: <CEL expression matching snapshot characteristics>
  priority: <0-100, higher = recommend first>

parameters:
  - name: <param>
    type: <string|bool|list>
    default: <value>

scope:
  services: ["auto"]          # auto-detect from snapshot

controls:
  include: ["auto"]           # auto-select matching controls

runbook:
  steps:
    - action: <eval|chain|report>
      args: { ... }

fixture:
  snapshot: "fixtures/snapshot.json"
  expected_findings: "fixtures/expected.jsonl"
  match_keys: ["control_id", "resource_id"]
```

The `recommend_when` predicate determines when the template is suggested based on snapshot content (e.g. service mix, account count, presence of specific data).

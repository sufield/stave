# chains/

Compound-risk chain definitions. Each YAML file describes a combination of single-resource controls that, when co-failing, produce a risk greater than any individual violation.

634 chains covering AWS, Azure, GCP, Kubernetes, Cisco, and cross-service attack paths.

## How Chains Work

A chain declares a set of controls and an `escalation_threshold`. When enough controls in the set fire simultaneously on evaluated observations, the chain produces a compound finding with its own `compound_severity` (typically higher than any individual control's severity).

```yaml
id: iam_dormant_escalation
description: >
  Switchable policy versions with broader permissions AND a principal
  that can create or switch policy versions.
controls:
  - CTL.IAM.POLICY.VERSIONS.001
  - CTL.IAM.ESCALATE.CREATEPOLICYVERSION.001
escalation_threshold: 2
compound_severity: critical
preconditions:
  - iam_credential_theft
postconditions:
  - shadow_admin_access
```

This chain fires only when *both* controls fail together -- dormant permissive policy versions exist AND a principal can activate them.

## Chain Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | yes | Unique chain identifier (snake_case) |
| `description` | yes | What the compound risk is and why the combination matters |
| `controls` | yes | List of control IDs that participate in the chain |
| `escalation_threshold` | yes | Minimum co-failing controls to trigger the chain |
| `compound_severity` | yes | Severity of the compound finding (`critical`, `high`, `medium`, `low`) |
| `preconditions` | no | Attack prerequisites (e.g. `data_access`, `iam_credential_theft`) |
| `postconditions` | no | What the attacker achieves (e.g. `data_destruction`, `shadow_admin_access`) |

## File Naming

Files are named `<domain>_<scenario>.yaml`. The domain prefix groups chains by service or attack surface (e.g. `iam_`, `s3_`, `apigw_`, `lambda_`, `azure_`, `gcp_`, `k8s_`).

## Usage

Chains are auto-discovered by `stave apply` from the `./chains` directory alongside the control catalog. They can also be rendered as graphs by `stave-mcp --render-chains`.

```bash
stave apply --observations obs/
```

The `stave forge chain` command scaffolds new chain files.

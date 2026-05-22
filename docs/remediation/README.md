# Structured Remediation Output

Stave produces machine-readable, IaC-agnostic property changes alongside
every finding. Any tool — Terraform, CDK, Pulumi, AWS CLI, or a human
at the console — can consume these and generate its own fix.

## Schema

Each finding's `remediation.changes[]` array contains `PropertyChange` entries:

```json
{
  "property_path": "properties.storage.public_access_block.block_public_acls",
  "current_value": "false",
  "required_value": "true",
  "resource_type": "aws_s3_bucket_public_access_block",
  "description": "Set block_public_acls to true",
  "has_safe_default": true
}
```

| Field | Description |
|-------|-------------|
| `property_path` | Observation property path (same as control predicates) |
| `current_value` | Value observed in the snapshot |
| `required_value` | Value needed to satisfy the control (empty if context-dependent) |
| `has_safe_default` | `true` = Stave knows the fix with certainty; `false` = needs human judgment |

## Confidence Score

`remediation.confidence` is a `float64` in `[0.0, 1.0]`:
- **1.0** — deterministic fix (boolean inversion, known required value)
- **0.7** — high confidence (likely correct, edge cases possible)
- **0.4** — low confidence (fix direction known, value needs context)

## Pipeline

```bash
# Assessment findings (JSON)
stave apply --observations ./observations --format json > remediation.json

# Generate Terraform patches
python3 docs/remediation/to-terraform.py < remediation.json > patches.tf

# Generate AWS CLI commands
python3 docs/remediation/to-aws-cli.py < remediation.json > fix.sh

# Filter to high-confidence changes only
cat remediation.json | jq '.entries[] | select(.remediation.confidence > 0.9)'
```

## Sample Scripts

- `to-terraform.py` — generates Terraform resource blocks for safe defaults
- `to-aws-cli.py` — generates AWS CLI commands for common services
- `to-checklist.md.py` — generates Markdown checklist grouped by confidence

These scripts are documentation examples, not production tools.

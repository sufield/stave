# OPA Rego Export

Export Stave controls to OPA Rego rules for use with Conftest, OPA, or
any Rego-based policy engine.

## Usage

```bash
# Export all S3 controls
stave export --format rego --controls controls/s3 > stave_s3.rego

# Export all controls with custom package
stave export --format rego --controls controls/ --package myorg.stave > policy/stave.rego

# Use with conftest
conftest test terraform.json --policy policy/
```

## Flags

| Flag | Default | Description |
|---|---|---|
| `--format, -f` | `rego` | Output format (currently only `rego`) |
| `--controls, -i` | `controls` | Path to control definitions directory |
| `--package` | `stave` | Rego package name |

## How it works

Each ctrl.v1 YAML control is translated to one or more Rego `deny[msg]`
rules:

- `all:` conditions become conjunctions in the rule body
- `any:` conditions become multiple rules (Rego's native OR)
- Nested `any:` inside `all:` generates helper rules
- Operators map directly: `eq`→`==`, `ne`→`!=`, `gt`→`>`, etc.
- `present`/`missing` map to existence checks
- Controls with predicate aliases are skipped (noted in comments)

## Example output

Input (CTL.S3.PUBLIC.001):
```yaml
unsafe_predicate:
  all:
    - field: properties.storage.kind
      op: eq
      value: bucket
    - field: properties.storage.access.public_read
      op: eq
      value: true
```

Output:
```rego
package stave

# CTL.S3.PUBLIC.001 — No Public S3 Bucket Read
# Severity: critical
deny[msg] {
    input.storage.kind == "bucket"
    input.storage.access.public_read == true
    msg := "CTL.S3.PUBLIC.001: No Public S3 Bucket Read"
}
```

## Using with Conftest

[Conftest](https://www.conftest.dev/) evaluates structured data against
OPA policies. After exporting Stave controls:

```bash
# Export controls
stave export --format rego --controls controls/s3 > policy/stave_s3.rego

# Test a Terraform plan
terraform show -json tfplan > plan.json
conftest test plan.json --policy policy/

# Test Kubernetes manifests
conftest test k8s-deployment.yaml --policy policy/
```

## Limitations

- Controls using `unsafe_predicate_alias` are skipped (no inline predicate to translate)
- `any_match`, `not_subset_of_field`, `neq_field`, `not_in_field` operators generate comments instead of Rego code
- Generated Rego uses `input.*` paths — the input document must match Stave's observation property structure
- Parameters (`params.*` references in values) are not resolved — they appear as literal strings

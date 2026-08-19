# Appendix C — Asset Types

Every observation asset has a `type` field. Controls bind to types via
`applicable_asset_types`.

## The Type System

Asset types are strings, not Go structs:

```go
// internal/core/kernel/asset_type.go
type AssetType string
```

The asset struct is generic:

```go
// internal/core/asset/models.go
type Asset struct {
    ID         ID
    Type       kernel.AssetType
    Vendor     kernel.Vendor
    Properties map[string]any
}
```

There are no per-asset-type structs. The schema is defined by convention:
the collector contract specifies which fields each type should have, and
control predicates reference those fields.

## How Controls Bind

```yaml
# From CTL.IAM.TRUST.MFA.001
applicable_asset_types:
  - aws_iam_role
```

This control evaluates only against assets with `type: aws_iam_role`. Assets
of other types are skipped. A control with `applicable_asset_types: [aws_s3_bucket]`
never evaluates IAM roles.

## Examples

| Type | Service | Example Control |
|------|---------|----------------|
| `aws_iam_role` | IAM | CTL.IAM.TRUST.MFA.001 |
| `aws_s3_bucket` | S3 | CTL.S3.PUBLIC.READ.001 |
| `aws_ec2_instance` | EC2 | CTL.EC2.SSM.ROLE.001 |
| `aws_ec2_account` | EC2 (account) | CTL.EC2.ALARM.STATUSCHECK.001 |
| `aws_rds_instance` | RDS | CTL.RDS.PUBLIC.001 |

## CLI

- `stave capabilities` — print supported input types
- `stave discover` — resolve AWS services to the data Stave needs

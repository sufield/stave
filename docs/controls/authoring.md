---
title: "Authoring Controls"
sidebar_label: "Authoring"
sidebar_position: 1
description: "How to write, test, and review custom Stave control definitions."
---

# Authoring Controls

This guide explains how to create new security controls for Stave. Controls are
declarative YAML — no Go code required. The evaluation engine handles any asset
type and any cloud vendor without code changes.

## Quick Start: Policy Forge

The fastest way to create a new control with test fixtures:

```bash
make forge \
  ID=CTL.S3.EXAMPLE.001 \
  NAME="Example Safety Check" \
  DOMAIN=exposure \
  SEVERITY=high \
  SCOPE_TAGS=aws,s3 \
  ASSET_TYPE=aws_s3_bucket \
  KIND=bucket \
  FIELD=properties.storage.access.public_read \
  OP=eq \
  VALUE=true \
  REMEDIATION="Enable S3 Public Access Block."
```

This generates:
- A validated ctrl.v1 YAML control definition
- A **fail** fixture (observations that trigger the finding, expected exit 3)
- A **pass** fixture (observations that do not trigger, expected exit 0)

Then generate golden files and run tests:

```bash
make golden
make e2e
```

## Folder Layout

Controls are organized by domain and category:

```
controls/
├── s3/                  # AWS S3 storage (67 controls)
├── iam/                 # AWS IAM identity (21 controls)
├── cloudwatch/          # AWS CloudWatch (17 controls)
├── rds/                 # AWS RDS (10 controls)
├── cloudtrail/          # AWS CloudTrail (7 controls)
├── vpc/                 # AWS VPC (7 controls)
├── gcs/                 # GCP Cloud Storage (7 controls)
├── ec2/                 # AWS EC2 (6 controls)
├── backup/              # Cross-service backup (6 controls)
├── k8s/                 # Kubernetes (8 controls)
├── elb/                 # AWS ELB (5 controls)
├── kms/                 # AWS KMS (4 controls)
├── config/              # AWS Config (3 controls)
├── secretsmanager/      # AWS Secrets Manager (3 controls)
├── dns/                 # DNS records — vendor-agnostic (3 controls)
├── dynamodb/            # AWS DynamoDB (2 controls)
├── sqs/                 # AWS SQS (3 controls)
├── sns/                 # AWS SNS (2 controls)
├── cloudformation/      # AWS CloudFormation (2 controls)
├── guardduty/           # AWS GuardDuty (2 controls)
├── securityhub/         # AWS Security Hub (2 controls)
├── autoscaling/         # AWS Auto Scaling (2 controls)
├── route53/             # AWS Route 53 (2 controls)
├── cognito/             # AWS Cognito (2 controls)
├── elasticache/         # AWS ElastiCache (2 controls)
└── apigateway/          # AWS API Gateway (2 controls)
```

Place new controls in the appropriate domain and category. Create a new
domain directory if no existing domain fits.

## Adding a New Domain

When adding controls for a new service or cloud provider:

1. Create `controls/{domain}/{category}/` directories
2. Document the property namespace in `docs/contract/README.md`
3. Add an INCOMPLETE control for missing extractor data
4. Update `internal/controldata/embed.go` with the new glob
5. Add pack and control entries to `internal/builtin/pack/embedded/index.yaml`
6. Optionally register a profile in `cmd/apply/profile.go`
7. Run `make sync-controls && make readme && make docs-controls`

Zero engine changes required. See AGENTS.md for the full checklist.

## ID Convention

```
CTL.<DOMAIN>.<CATEGORY>.<SEQ>
```

- **DOMAIN**: Service identifier (`S3`, `IAM`, `GCS`, `DNS`)
- **CATEGORY**: What it checks (`PUBLIC`, `ENCRYPT`, `ROOT`, `DANGLING`)
- **SEQ**: Three-digit sequence number (`001`, `002`, etc.)

Multi-segment categories are allowed: `CTL.S3.PUBLIC.PREFIX.001`,
`CTL.IAM.ROOT.MFA.001`, `CTL.DNS.DANGLING.001`.

The ID must match: `^CTL\.[A-Z0-9]+\.[A-Z0-9]+(\.[A-Z0-9]+)*\.[0-9]+$`

## Control Structure

```yaml
dsl_version: ctrl.v1
id: CTL.S3.EXAMPLE.001
name: Example Safety Check
description: >
  Buckets must not have public read access enabled.
domain: exposure
severity: high
compliance:
  cis_aws_v1.4.0: "2.1.5"
  hipaa: "164.312(a)(1)"
scope_tags:
  - aws
  - s3
type: unsafe_state
params: {}
remediation:
  description: >
    Bucket has public read access. Anyone can download objects.
  action: >
    Enable S3 Public Access Block (all four settings).
  example: |
    {
      "storage": {
        "access": { "public_read": false }
      }
    }
unsafe_predicate:
  all:
    - field: properties.storage.kind
      op: eq
      value: bucket
    - field: properties.storage.access.public_read
      op: eq
      value: true
```

### Required fields

| Field | Purpose |
|-------|---------|
| `dsl_version` | Must be `ctrl.v1` |
| `id` | Unique control identifier |
| `name` | Short human-readable name |
| `description` | What the control detects and why it matters |
| `type` | Control type (see below) |
| `unsafe_predicate` | YAML predicate defining the unsafe condition |

### Recommended fields

| Field | Purpose |
|-------|---------|
| `domain` | Grouping label (`exposure`, `identity`, `storage`) |
| `severity` | `critical`, `high`, `medium`, `low`, `info` |
| `scope_tags` | Array of tags for filtering (`aws`, `s3`, `gcp`, `dns`) |
| `compliance` | Framework mappings (`hipaa`, `cis_aws_v1.4.0`, `pci_dss_v3.2.1`) |
| `remediation` | Description, action, and example for fixing the finding |

## Operator Reference

| Operator | What it does | Example |
|----------|-------------|---------|
| `eq` | Equality check | `{field: ..., op: eq, value: true}` |
| `ne` | Not equal (missing fields match) | `{field: ..., op: ne, value: "aws:kms"}` |
| `gt` | Greater than (numeric) | `{field: ..., op: gt, value: 10}` |
| `lt` | Less than (numeric) | `{field: ..., op: lt, value: 14}` |
| `gte` | Greater than or equal | `{field: ..., op: gte, value: 2190}` |
| `lte` | Less than or equal | `{field: ..., op: lte, value: 90}` |
| `in` | Value in list | `{field: ..., op: in, value: [PII, PHI]}` |
| `missing` | Field absent/nil/empty | `{field: ..., op: missing, value: true}` |
| `present` | Field exists and non-empty | `{field: ..., op: present, value: true}` |
| `contains` | Substring match | `{field: ..., op: contains, value: "enforce_prefix=false"}` |
| `any_match` | Nested predicate over array | See [Array matching](#array-matching) |
| `neq_field` | Two fields not equal | `{field: ..., op: neq_field, value: ...}` |
| `not_in_field` | Value not in another field's list | `{field: ..., op: not_in_field, value: ...}` |
| `list_empty` | List is empty or nil | `{field: ..., op: list_empty, value: true}` |
| `not_subset_of_field` | List has elements not in another | `{field: ..., op: not_subset_of_field, value: ...}` |

**Notes:**
- Missing fields do **not** match `eq false`. Only explicitly set `false` triggers `eq false`.
- Missing fields **do** match `ne "value"`. Absence counts as "not equal."

## Common Patterns

### Boolean state check

```yaml
unsafe_predicate:
  any:
    - field: properties.storage.access.public_read
      op: eq
      value: true
```

### Kind discriminator + property check

Most controls start with a `kind` check to scope the predicate to the right
asset subtype. The Policy Forge generates this automatically with `--kind`.

```yaml
unsafe_predicate:
  all:
    - field: properties.identity.kind
      op: eq
      value: user
    - field: properties.identity.console_access.mfa_enabled
      op: eq
      value: false
```

### Nested `any` inside `all` (compound condition)

```yaml
unsafe_predicate:
  all:
    - field: properties.identity.kind
      op: eq
      value: password_policy
    - any:
        - field: properties.identity.password_policy.require_uppercase
          op: eq
          value: false
        - field: properties.identity.password_policy.require_symbols
          op: eq
          value: false
```

### Data classification + access check

```yaml
unsafe_predicate:
  all:
    - any:
        - field: properties.storage.access.public_read
          op: eq
          value: true
    - any:
        - field: properties.storage.tags.data-classification
          op: eq
          value: confidential
        - field: properties.storage.tags.data-classification
          op: eq
          value: phi
```

### Array matching (identity iteration)

Use `any_match` to evaluate a nested predicate against each element of an
array field (e.g., identities):

```yaml
unsafe_predicate:
  all:
    - field: properties.storage.tags.tenant_mode
      op: eq
      value: shared
    - field: identities
      op: any_match
      value:
        all:
          - field: type
            op: eq
            value: app_signer
          - field: purpose
            op: contains
            value: "allow_traversal=true"
```

### Vendor-agnostic controls

DNS controls work regardless of DNS provider. The `vendor` field is metadata —
controls evaluate `properties.dns.*` paths only:

```yaml
unsafe_predicate:
  any:
    - field: properties.dns.target_exists
      op: eq
      value: false
    - field: properties.dns.target_owned
      op: eq
      value: false
```

## Control Types

| Type | When to use |
|------|------------|
| `unsafe_state` | Violation when predicate matches in any snapshot. Most common. |
| `unsafe_duration` | Violation when asset is unsafe longer than `--max-unsafe`. |
| `prefix_exposure` | Violation when protected prefixes are publicly readable. |
| `unsafe_recurrence` | Violation when exposure window count exceeds limit within window. |

For `unsafe_duration`, set a per-control threshold to override `--max-unsafe`:

```yaml
type: unsafe_duration
params:
  max_unsafe_duration: "0h"   # zero tolerance — immediate violation
```

## Property Namespaces

Each domain uses its own namespace. See `docs/contract/README.md` for the
full field dictionary.

| Domain | Namespace | Discriminator |
|--------|-----------|---------------|
| S3 | `properties.storage.*` | `storage.kind: "bucket"` |
| IAM | `properties.identity.*` | `identity.kind: "account"/"user"/"password_policy"` |
| GCS | `properties.storage.*` | `storage.kind: "bucket"` (shared with S3 where semantics align) |
| DNS | `properties.dns.*` | — (vendor-agnostic) |

## Testing Your Control

### Using the Policy Forge (recommended)

```bash
# Generate control + pass/fail fixtures
make forge ID=CTL.S3.NEW.001 NAME="My Control" \
  FIELD=properties.storage.access.public_read \
  REMEDIATION="Disable public read."

# Generate golden expected output
make golden

# Run all E2E tests including the new fixture
make e2e
```

### Manual testing

```bash
# Validate schema
stave validate --in controls/s3/example/CTL.S3.EXAMPLE.001.yaml

# Evaluate against test observations
stave apply \
  --controls controls/s3/example/ \
  --observations test-observations/ \
  --now 2026-01-02T00:00:00Z \
  --allow-unknown-input

# Trace evaluation logic step by step
stave apply \
  --controls controls/s3/example/ \
  --observations test-observations/ \
  --now 2026-01-02T00:00:00Z \
  --allow-unknown-input \
  --trace trace.json
```

## Review Checklist

Before submitting a new control:

- [ ] ID follows `CTL.<DOMAIN>.<CATEGORY>.<SEQ>` pattern
- [ ] `dsl_version` is `ctrl.v1`
- [ ] `name` and `description` are clear and specific
- [ ] `remediation.action` explains how to fix (required — every control must have a remediation path)
- [ ] `severity` is set
- [ ] `scope_tags` include domain and vendor tags
- [ ] `compliance` references added where applicable
- [ ] Control passes `stave validate`
- [ ] Pass and fail test fixtures exist
- [ ] Golden-file output committed for regression testing
- [ ] Property namespace documented in `docs/contract/README.md`
- [ ] INCOMPLETE control exists for the domain

## Build Integration

After adding controls:

```bash
make sync-controls      # Copy to embedded directory
make build              # Rebuild binary with new controls
make docs-controls      # Regenerate control reference
make readme             # Update README with control counts
make e2e                # Verify all tests pass
```

## Further Reading

- [Observation Contract](../contract/README.md) — property namespace specification
- [Control Reference](reference.md) — auto-generated reference for all built-in controls
- [Evaluation Semantics](../evaluation-semantics.md) — how duration tracking works

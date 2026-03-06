---
title: "Authoring Controls"
sidebar_label: "Authoring"
sidebar_position: 1
description: "How to write, test, and review custom Stave control definitions."
---

# Authoring Controls

This guide explains how to write new control definitions for Stave.

## Folder Layout

S3 controls are organized by category under `controls/s3/`:

```
controls/s3/
├── public/              # Public exposure (PUBLIC.001–006, LIST, PREFIX, etc.)
├── access/              # Cross-account access (ACCESS.001–003, AUTH.READ/WRITE)
├── acl/                 # ACL privilege escalation (ESCALATION, RECON, FULLCONTROL)
├── encrypt/             # Encryption requirements (ENCRYPT.001–004)
├── versioning/          # Versioning (VERSION.001–002)
├── logging/             # Access logging (LOG.001)
├── lifecycle/           # Lifecycle rules (LIFECYCLE.001–002)
├── lock/                # Object lock (LOCK.001–003)
├── network/             # Network conditions (NETWORK.001)
├── governance/          # Tagging and governance (GOVERNANCE.001)
├── write_scope/         # Upload policy scoping (WRITE.SCOPE, WRITE.CONTENT)
├── tenant/              # Tenant isolation (TENANT.ISOLATION.001)
├── takeover/            # Bucket takeover (BUCKET.TAKEOVER, DANGLING.ORIGIN)
├── artifacts/           # Repository artifacts (REPO.ARTIFACT.001)
└── misc/                # Controls and completeness (CONTROLS, INCOMPLETE)
```

Place new controls in the appropriate category directory. Create a new directory if no existing category fits.

## ID Convention

```
CTL.<VENDOR>.<CATEGORY>.<SEQ>
```

- **VENDOR**: Service identifier (`S3`, `IAM`, etc.)
- **CATEGORY**: What it checks (`PUBLIC`, `ENCRYPT`, `ACCESS`, etc.)
- **SEQ**: Three-digit sequence number (`001`, `002`, etc.)

Multi-segment categories are allowed: `CTL.S3.PUBLIC.PREFIX.001`, `CTL.S3.ACL.ESCALATION.001`.

The ID must match the regex: `^CTL\.[A-Z0-9]+\.[A-Z0-9]+(\.[A-Z0-9]+)*\.[0-9]+$`

## Minimal Example

```yaml
dsl_version: ctrl.v1
id: CTL.S3.EXAMPLE.001
name: Example Safety Check
description: >
  Buckets must not have example_flag set to true.
domain: exposure
scope_tags:
  - aws
  - s3
type: unsafe_state
unsafe_predicate:
  any:
    - field: properties.storage.example_flag
      op: eq
      value: true
remediation:
  description: >
    Bucket has example_flag enabled. This is a placeholder control.
  action: >
    Set example_flag to false in the bucket configuration.
```

## Operator Reference

| Operator | What it does | Example |
|----------|-------------|---------|
| `eq` | Equality check | `{field: properties.storage.visibility.public_read, op: eq, value: true}` |
| `ne` | Not equal (missing fields match) | `{field: properties.storage.encryption.algorithm, op: ne, value: "aws:kms"}` |
| `gt` | Greater than (numeric) | `{field: properties.storage.lifecycle.rule_count, op: gt, value: 10}` |
| `lt` | Less than (numeric) | `{field: properties.storage.lifecycle.rule_count, op: lt, value: 1}` |
| `gte` | Greater than or equal | `{field: properties.storage.object_lock.retention_days, op: gte, value: 2190}` |
| `lte` | Less than or equal | `{field: properties.storage.object_lock.retention_days, op: lte, value: 90}` |
| `in` | Value in list | `{field: properties.storage.tags.data-classification, op: in, value: [PII, PHI]}` |
| `missing` | Field absent/nil/empty | `{field: properties.storage.encryption.kms_key_id, op: missing, value: true}` |
| `present` | Field exists and non-empty | `{field: properties.storage.tags.tenant_prefix, op: present, value: true}` |
| `contains` | Substring match | `{field: properties.storage.tags.purpose, op: contains, value: "enforce_prefix=false"}` |
| `any_match` | Nested predicate over array | See [Array matching](#array-matching) |
| `neq_field` | Two fields not equal | `{field: properties.owner, op: neq_field, value: properties.expected_owner}` |
| `not_in_field` | Value not in another field's list | `{field: properties.role, op: not_in_field, value: properties.allowed_roles}` |
| `list_empty` | List is empty or nil | `{field: properties.audience, op: list_empty, value: true}` |
| `not_subset_of_field` | List has elements not in another | `{field: properties.scopes, op: not_subset_of_field, value: properties.allowed_scopes}` |

**Semantic notes:**
- Missing fields do **not** match `eq false`. Only explicitly set `false` triggers `eq false`.
- Missing fields **do** match `ne "value"`. Absence counts as "not equal."

## Common Patterns

### Boolean state check

```yaml
unsafe_predicate:
  any:
    - field: properties.storage.visibility.public_read
      op: eq
      value: true
    - field: properties.storage.visibility.public_list
      op: eq
      value: true
```

### Combined type + property check

```yaml
unsafe_predicate:
  all:
    - field: properties.storage.kind
      op: eq
      value: bucket
    - field: properties.storage.access.has_external_access
      op: eq
      value: true
```

### Missing field detection

```yaml
unsafe_predicate:
  all:
    - field: properties.storage.tags.data-classification
      op: eq
      value: "phi"
    - field: properties.storage.encryption.kms_key_id
      op: missing
      value: true
```

### Numeric threshold

```yaml
unsafe_predicate:
  all:
    - field: properties.storage.lifecycle.rule_count
      op: lt
      value: 1
```

### Array matching

Use `any_match` to evaluate a nested predicate against each element of an array field (e.g., identities):

```yaml
unsafe_predicate:
  any:
    - field: identities
      op: any_match
      value:
        all:
          - field: type
            op: eq
            value: app_signer
          - field: purpose
            op: contains
            value: "enforce_prefix=false"
```

## Control Types

| Type | When to use |
|------|------------|
| `unsafe_state` | Violation when predicate matches in any snapshot. Most common. |
| `unsafe_duration` | Violation when resource is unsafe longer than `--max-unsafe`. |
| `prefix_exposure` | Violation when protected prefixes are publicly readable. |
| `unsafe_recurrence` | Violation when episode count exceeds limit within window. |

For `unsafe_duration`, you can set a per-control threshold:

```yaml
params:
  max_unsafe_duration: "24h"
```

This overrides the CLI `--max-unsafe` flag for that specific control.

## Schema Validation

`stave validate` performs full [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12) validation against the canonical schema files embedded in the binary. Both controls and observations are validated before evaluation begins — you do not need to validate separately unless you want early feedback while authoring.

### What gets validated

| Input | Schema | Invoked via |
|-------|--------|-------------|
| Observation JSON | [`obs.v0.1.schema.json`](../../schemas/obs.v0.1.schema.json) | `stave validate --in <file>` or `--observations <dir>` |
| Control YAML | [`ctrl.v1.schema.json`](../../schemas/ctrl.v1.schema.json) | `stave validate --in <file>` or `--controls <dir>` |

Control YAML is converted to JSON internally before schema validation runs.

### What the schema enforces

| Constraint | Control (`ctrl.v1`) | Observation (`obs.v0.1`) |
|------------|----------------------|------------------------|
| `additionalProperties: false` | Yes — extra fields cause rejection | Yes — no `"snapshots"` wrapper, no unknown fields |
| Required fields | `dsl_version`, `id`, `name`, `description`, `unsafe_predicate` | `schema_version`, `captured_at`, `resources` |
| `const` version | `dsl_version` must be `"ctrl.v1"` | `schema_version` must be `"obs.v0.1"` |
| ID pattern | Must match `^CTL\.[A-Z0-9]+\.[A-Z0-9]+(\.[A-Z0-9]+)*\.[0-9]+$` | — |
| `enum` values | `domain`: exposure, identity, storage, platforms, third_party | — |
| | `severity`: critical, high, medium, low, info | — |
| | `op`: 15 allowed operators (eq, ne, gt, lt, ...) | — |
| Timestamp format | — | `captured_at` must be RFC 3339 (`date-time`) |
| String minimums | `id`, `name`, `description` must be non-empty (minLength: 1) | Resource `id`, `type`, `vendor` must be non-empty |
| Nested structure | `unsafe_predicate` must contain `any` or `all` arrays | `resources` items require `id`, `type`, `vendor`, `properties` |

### Common validation errors

| Error | Cause | Fix |
|-------|-------|-----|
| `additionalProperties 'foo' not allowed` | Extra field in YAML/JSON | Remove the field or check for typos |
| `missing properties: 'unsafe_predicate'` | Required field absent | Add the missing field |
| `'ctrl.v0.2' is not valid ... const 'ctrl.v1'` | Wrong DSL version string | Use `dsl_version: ctrl.v1` |
| `'CTL.s3.public.001' does not match pattern` | ID has lowercase letters | Use uppercase: `CTL.S3.PUBLIC.001` |
| `'foo' is not valid ... enum` | Invalid `op`, `domain`, or `severity` | Check allowed values in the schema |

### Validate commands

```bash
# Validate a single control
stave validate --in controls/s3/example/CTL.S3.EXAMPLE.001.yaml

# Validate all controls in a directory
stave validate --controls controls/s3/

# Validate a single observation
stave validate --in observations/2026-01-01T00:00:00Z.json

# Validate all observations in a directory
stave validate --observations observations/

# Validate from stdin
cat snapshot.json | stave validate --in -

# JSON output for programmatic use
stave validate --controls controls/s3/ --format json
```

Exit codes: 0 = valid, 2 = validation errors found.

## Testing Your Control

### 1. Validate schema

```bash
stave validate --in controls/s3/example/CTL.S3.EXAMPLE.001.yaml
```

### 2. Create test observations

Write two observation snapshots with the condition your control should detect:

```json
{
  "schema_version": "obs.v0.1",
  "captured_at": "2026-01-01T00:00:00Z",
  "resources": [{
    "id": "res:aws:s3:bucket:test-bucket",
    "type": "storage_bucket",
    "vendor": "aws",
    "properties": {
      "storage": { "example_flag": true }
    }
  }]
}
```

### 3. Evaluate

```bash
stave apply \
  --controls controls/s3/example/ \
  --observations test-observations/ \
  --now 2026-01-02T00:00:00Z \
  --allow-unknown-input
```

Expected: exit code 3 (violations found).

### 4. Golden-file test

Save the expected output and diff against future runs:

```bash
stave apply \
  --controls controls/s3/example/ \
  --observations test-observations/ \
  --now 2026-01-02T00:00:00Z \
  --allow-unknown-input > expected.json

# Later: verify no regression
stave apply \
  --controls controls/s3/example/ \
  --observations test-observations/ \
  --now 2026-01-02T00:00:00Z \
  --allow-unknown-input | diff - expected.json
```

## Review Checklist

Before submitting a new control:

- [ ] ID follows `CTL.<VENDOR>.<CATEGORY>.<SEQ>` pattern
- [ ] `dsl_version` is `ctrl.v1`
- [ ] `name` and `description` are clear and specific
- [ ] `unsafe_predicate` uses only operators from the [schema](../schema/ctrl.v1.md)
- [ ] `remediation.description` and `remediation.action` explain the risk and fix
- [ ] Control passes `stave validate`
- [ ] Test observations trigger the expected finding
- [ ] Golden-file output committed for regression testing
- [ ] Placed in the correct category directory

## Further Reading

- [Control Schema Reference](../schema/ctrl.v1.md)
- [Observation Schema Reference](../schema/obs.v0.1.md)
- [Evaluation Engine Capabilities](../evaluation-engine-capabilities.md)

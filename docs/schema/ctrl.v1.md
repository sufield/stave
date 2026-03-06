---
title: "Control Schema (ctrl.v1)"
sidebar_label: "ctrl.v1"
sidebar_position: 3
description: "Reference for the ctrl.v1 control definition schema."
---

# Control Schema — `ctrl.v1`

Schema ID: `urn:stave:schema:control:v0.1`

A control defines a safety rule that infrastructure assets must satisfy. Controls are written in YAML and evaluated against observation snapshots.

## Top-Level Structure

```yaml
dsl_version: ctrl.v1
id: CTL.S3.PUBLIC.001
name: No Public S3 Buckets
description: >
  S3 buckets must not allow public read or list access.
domain: exposure
scope_tags: [aws, s3]
type: unsafe_state
severity: critical
compliance:
  cis_aws_v1.4.0: "2.1.5"
  pci_dss_v3.2.1: "1.2.1"
  soc2: "CC6.1"
params: {}
unsafe_predicate_alias: s3.is_public_readable
remediation:
  description: Bucket has public read access enabled.
  action: Enable S3 Public Access Block.
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `dsl_version` | string | Yes | Must be `"ctrl.v1"` |
| `id` | string | Yes | Control ID matching `^CTL\.[A-Z0-9]+\.[A-Z0-9]+(\.[A-Z0-9]+)*\.[0-9]+$` |
| `name` | string | Yes | Human-readable name |
| `description` | string | Yes | What the control checks |
| `domain` | enum | No | `exposure`, `identity`, `storage`, `platforms`, `third_party` |
| `scope_tags` | array of strings | No | Vendor/technology tags (e.g., `aws`, `s3`) |
| `version` | string | No | Version identifier |
| `type` | string | No | Control type (e.g., `unsafe_state`, `unsafe_duration`) |
| `severity` | enum | No | `critical`, `high`, `medium`, `low`, `info` |
| `compliance` | object | No | Compliance framework mappings (framework name → control ID) |
| `params` | object | No | Configurable parameters |
| `unsafe_predicate` | [predicate](#predicate) | Conditionally | Conditions that make an asset unsafe |
| `unsafe_predicate_alias` | string | Conditionally | Built-in semantic alias expanded during load (for example `s3.is_public_readable`) |
| `scope` | object | No | Scope rules to limit which assets are evaluated |
| `scope.exclude` | [predicate](#predicate) | No | Resources matching this predicate are excluded |
| `remediation` | [remediation](#remediation) | No | Remediation guidance |

## ID Convention

Control IDs follow the pattern `CTL.<VENDOR>.<CATEGORY>.<SEQ>`:

```
CTL.S3.PUBLIC.001
 │   │    │     └── Sequence number
 │   │    └──────── Category (PUBLIC, ENCRYPT, ACCESS, etc.)
 │   └───────────── Vendor/service (S3, IAM, etc.)
 └───────────────── Prefix (always CTL)
```

Multi-segment categories are allowed: `CTL.S3.PUBLIC.PREFIX.001`, `CTL.S3.ACL.ESCALATION.001`.

## Predicate

A predicate defines unsafe conditions using boolean logic. It contains either `any` (OR) or `all` (AND), each holding an array of rules.

```yaml
# OR: any one match triggers
unsafe_predicate:
  any:
    - field: properties.storage.visibility.public_read
      op: eq
      value: true
    - field: properties.storage.visibility.public_list
      op: eq
      value: true

# AND: all must match
unsafe_predicate:
  all:
    - field: properties.storage.kind
      op: eq
      value: bucket
    - field: properties.storage.access.has_external_access
      op: eq
      value: true
```

Predicates can be nested — rules may contain their own `any`/`all` blocks for complex logic.

You can also use a built-in alias instead of writing predicate rules manually:

```yaml
unsafe_predicate_alias: s3.is_public_writable
```

Exactly one of `unsafe_predicate` or `unsafe_predicate_alias` must be present.

## Predicate Operators

The DSL supports 15 operators:

| Operator | Description | Value type |
|----------|-------------|------------|
| `eq` | Equals | string, bool, numeric |
| `ne` | Not equals (missing fields match) | string, bool, numeric |
| `gt` | Greater than | numeric |
| `lt` | Less than | numeric |
| `gte` | Greater than or equal | numeric |
| `lte` | Less than or equal | numeric |
| `in` | Value in list | array |
| `missing` | Field absent, nil, or empty | boolean (`true`) |
| `present` | Field exists and non-empty | boolean (`true`) |
| `contains` | String contains substring | string |
| `any_match` | Any array element matches nested predicate | nested predicate |
| `neq_field` | Value not equal to another field | field path |
| `not_in_field` | Value not in another field's list | field path |
| `list_empty` | List field is empty or nil | boolean (`true`) |
| `not_subset_of_field` | List has elements not in another field | field path |

**Predicate semantics to note:**

- Missing fields do **not** match `eq false` — only explicitly set `false` triggers `eq false`.
- Missing fields **do** match `ne "value"` — absence counts as "not equal."
- `value_from_param` can reference a key in the control's `params` section instead of a literal `value`.

## Remediation

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `description` | string | Yes | What the violation means |
| `action` | string | Yes | How to remediate |
| `example` | string | No | Example safe configuration |

## Control Types

| Type | Behavior |
|------|----------|
| `unsafe_state` | Violation when predicate matches in any snapshot |
| `unsafe_duration` | Violation when asset is unsafe longer than `--max-unsafe` threshold |
| `unsafe_recurrence` | Violation when episode count exceeds limit within window |
| `prefix_exposure` | Violation when protected prefixes are publicly readable |

## File Layout

Controls are organized by vendor and category:

```
controls/s3/
├── public/          # Public exposure checks
├── access/          # Cross-account access
├── acl/             # ACL privilege checks
├── encrypt/         # Encryption requirements
├── versioning/      # Versioning requirements
├── logging/         # Access logging
├── lifecycle/       # Lifecycle rules
├── lock/            # Object lock
├── network/         # Network conditions
├── governance/      # Tagging and governance
├── write_scope/     # Upload policy scoping
├── tenant/          # Tenant isolation
├── takeover/        # Bucket takeover
├── artifacts/       # Repository artifacts
└── misc/            # Controls and completeness
```

## Validation

`stave validate` performs full [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12) validation using the [`santhosh-tekuri/jsonschema`](https://github.com/santhosh-tekuri/jsonschema) library. Control YAML is converted to JSON internally before schema validation runs. The schema is embedded in the binary — no external files or network access needed.

Validation also runs automatically at the start of `stave apply`, so controls are always checked before evaluation begins.

### What the schema enforces

| Constraint | Detail |
|------------|--------|
| `additionalProperties: false` | Extra fields are rejected at every level — typos in field names cause immediate failure |
| Required fields | `dsl_version`, `id`, `name`, `description`, and one of `unsafe_predicate`/`unsafe_predicate_alias` |
| `const` version | `dsl_version` must be exactly `"ctrl.v1"` |
| ID pattern | Must match `^CTL\.[A-Z0-9]+\.[A-Z0-9]+(\.[A-Z0-9]+)*\.[0-9]+$` |
| `enum` for `domain` | `exposure`, `identity`, `storage`, `platforms`, `third_party` |
| `enum` for `severity` | `critical`, `high`, `medium`, `low`, `info` |
| `enum` for `op` | 15 allowed operators: `eq`, `ne`, `gt`, `lt`, `gte`, `lte`, `in`, `missing`, `present`, `contains`, `any_match`, `neq_field`, `not_in_field`, `list_empty`, `not_subset_of_field` |
| String minimums | `id`, `name`, `description` must be non-empty (`minLength: 1`) |
| Remediation required fields | If `remediation` is present, `description` and `action` are required |
| Predicate structure | `unsafe_predicate` must contain `any` or `all` arrays of predicate rules |

### Commands

```bash
# Validate a single control
stave validate --in controls/s3/public/CTL.S3.PUBLIC.001.yaml

# Validate all controls in a directory
stave validate --controls controls/s3/

# JSON output for programmatic use
stave validate --controls controls/s3/ --format json
```

Exit codes: 0 = valid, 2 = validation errors found.

## Schema Source

The canonical schema file is [`schemas/ctrl.v1.schema.json`](../../schemas/ctrl.v1.schema.json).

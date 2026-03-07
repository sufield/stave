# Evaluation Engine Capabilities

This document maps what the Stave evaluation engine supports vs. what MVP 1.0
S3 controls actually exercise. It is written for reviewers evaluating the
codebase and for the team deciding which capabilities to promote in MVP 1.0+.

## Why this document exists

The evaluation engine was designed to support multiple configuration domains
(storage, identity, process boundaries). MVP 1.0 ships only S3 controls. The
engine code that S3 controls don't exercise is intentionally retained — it is
**candidate enabling code for MVP 1.0+** and will be reviewed to decide whether
it stays, gets promoted, or gets removed.

This document prevents confusion: a reviewer seeing `gt` or `list_empty` in the
predicate engine should understand that these operators work, are tested, and
exist because the engine was designed for more than one domain.

## Predicate operators

The engine implements 15 predicate operators. S3 controls use 7 of them.

### Used by S3 controls (MVP 1.0)

| Operator | What it does | Example S3 control |
|----------|-------------|---------------------|
| `eq` | Equality | `CTL.S3.PUBLIC.001` — `public_read eq true` |
| `ne` | Not equal (missing fields match) | `CTL.S3.ENCRYPT.001` — `algorithm ne "aws:kms"` |
| `lt` | Less than (numeric) | `CTL.S3.LIFECYCLE.EXPIRY.001` — `rule_count lt 1` |
| `missing` | Field absent/nil/empty | `CTL.S3.ENCRYPT.002` — `kms_key_id missing` |
| `present` | Field exists and non-empty | `CTL.S3.TENANT.ISOLATION.001` — `tenant_prefix present` |
| `contains` | Substring match | `CTL.S3.TENANT.ISOLATION.001` — `purpose contains "enforce_prefix=false"` |
| `any_match` | Nested predicate over array | `CTL.S3.TENANT.ISOLATION.001` — matches identities |

### Not used by S3 controls (MVP 1.0+ candidate)

| Operator | What it does | Designed for |
|----------|-------------|-------------|
| `gt` | Greater than | Identity blast-radius checks (`distinct_systems > max`) |
| `gte` | Greater than or equal | Numeric thresholds |
| `lte` | Less than or equal | Numeric thresholds |
| `in` | Value in list | Data-classification matching (`in: [PII, PHI, PCI]`) |
| `list_empty` | List field is empty/nil | Audience verification (`intended_audience` empty) |
| `not_subset_of_field` | List A not subset of list B | Audience mismatch detection |
| `neq_field` | Two fields not equal | Cross-subject access checks |
| `not_in_field` | Value not in another field's list | Allowlist enforcement |

All 15 operators are tested in `internal/domain/control_test.go`.

## Control types

The engine defines 9 control types. 4 are evaluatable; S3 controls use 3.

### Evaluated and used by S3 (MVP 1.0)

| Type | S3 controls using it |
|------|----------------------|
| `unsafe_state` | 38 of 40 S3 controls |
| `unsafe_duration` | 2 S3 controls (`CTL.S3.PUBLIC.DURATION.001`, `CTL.S3.PUBLIC.DURATION.002`) |
| `prefix_exposure` | 1 S3 control (`CTL.S3.PUBLIC.PREFIX.001`) — violation when protected prefixes are publicly readable |

### Evaluated but not used by S3 (MVP 1.0+ candidate)

| Type | What it does | Code location |
|------|-------------|---------------|
| `unsafe_recurrence` | Violation when episode count exceeds limit within window | `evaluator_run.go` |

### Defined but not evaluated (MVP 1.0+ candidate)

| Type | Planned purpose |
|------|----------------|
| `authorization_boundary` | Identity boundary controls |
| `audience_boundary` | Audience verification |
| `justification_required` | Business justification for public access |
| `ownership_required` | Owner assignment for public assets |
| `visibility_required` | Exposure status must be known |

Controls using non-evaluatable types appear in the `skipped` section of
evaluate output with reason "type not supported."

## Identity model

The engine supports identity evaluation for tenant-isolation and blast-radius
controls. S3 controls use a subset.

### Used by S3 (MVP 1.0)

| Field | Used by |
|-------|---------|
| `identities` (array on snapshot) | `CTL.S3.TENANT.ISOLATION.001` via `any_match` |
| `identity.type` | Tenant isolation — matches `app_signer` |
| `identity.id` | Tenant isolation — identity identification |
| `identity.purpose` | Tenant isolation — checks for `enforce_prefix`, `allow_traversal` |

### Not used by S3 (MVP 1.0+ candidate)

| Field | Designed for |
|-------|-------------|
| `identity.owner` | Blast-radius checks — require owner attribution |
| `identity.grants.has_wildcard` | Blast-radius checks — detect wildcard permissions |
| `identity.scope.distinct_systems` | Blast-radius checks — limit cross-system access |
| `identity.scope.distinct_resource_groups` | Blast-radius checks — limit resource group span |

The `EvaluateIdentity()` method and `NewIdentityEvalContext()` function exist
for first-class identity evaluation (identities as evaluation subjects, not just
nested array items). No S3 control invokes this path.

## Parameter substitution

Controls can use `value_from_param` to reference parameters defined in the
control's `params` section. No S3 control uses this — all S3 predicates
specify literal values directly. The mechanism exists for parameterized
controls where thresholds vary per deployment.

## Catalog

The hardcoded catalog in `catalog.go` lists control entries for validation and
documentation. After the MVP 1.0 cleanup, remaining entries are all in the
`EXP` (exposure) and `META` domains. The catalog does not drive evaluation — S3
controls are loaded from YAML files on disk.

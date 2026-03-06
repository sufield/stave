---
title: "Observation Schema (obs.v0.1)"
sidebar_label: "obs.v0.1"
sidebar_position: 1
description: "Reference for the obs.v0.1 observation snapshot schema."
---

# Observation Schema — `obs.v0.1`

Schema ID: `urn:stave:schema:observation:v0.1`

An observation is a point-in-time snapshot of infrastructure assets. Each JSON file represents one capture timestamp. Stave requires **at least two snapshots** (two points in time) for duration-based controls to calculate unsafe periods.

## Top-Level Structure

```json
{
  "schema_version": "obs.v0.1",
  "generated_by": { ... },
  "captured_at": "2026-01-15T00:00:00Z",
  "assets": [ ... ],
  "identities": [ ... ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | string | Yes | Must be `"obs.v0.1"` |
| `generated_by` | object | No | Tool that generated this observation |
| `captured_at` | string (date-time) | Yes | RFC 3339 timestamp of capture |
| `assets` | array of [resource](#resource) | Yes | Infrastructure resources |
| `identities` | array of [identity](#identity) | No | IAM identities |

The schema uses `additionalProperties: false` at every level. Extra fields cause validation failure.

## `generated_by`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `source_type` | string | No | Source type identifier (e.g., `terraform.plan_json`) |
| `tool` | string | No | Tool name |
| `tool_version` | string | No | Tool version |
| `provider` | string | No | Provider name |
| `provider_version` | string | No | Provider version |

The `source_type` field is validated against a built-in allowlist by default. Use `--allow-unknown-input` to accept custom source types not in the allowlist.

Run `stave capabilities` to see the current allowlist.

## Resource

Each resource represents a single infrastructure component.

```json
{
  "id": "res:aws:s3:bucket:my-bucket",
  "type": "storage_bucket",
  "vendor": "aws",
  "properties": {
    "storage": {
      "visibility": { "public_read": true }
    }
  },
  "source": { "file": "infra/main.tf", "line": 42 }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique resource identifier (min 1 char) |
| `type` | string | Yes | Resource type (e.g., `storage_bucket`, `iam_role`) |
| `vendor` | string | Yes | Cloud vendor (e.g., `aws`, `gcp`, `azure`) |
| `properties` | object | Yes | Resource properties for predicate evaluation |
| `source` | [source_ref](#source-reference) | No | Source file reference |

The `properties` object is free-form — its structure depends on the asset type. Control predicates reference fields within `properties` using dot-notation paths (e.g., `properties.storage.visibility.public_read`).

## Identity

Each identity represents an IAM principal.

```json
{
  "id": "arn:aws:iam::123456789012:role/app-signer",
  "type": "iam_role",
  "vendor": "aws",
  "grants": { "has_wildcard": false },
  "scope": { "distinct_systems": 1, "distinct_resource_groups": 2 }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identity identifier |
| `type` | string | Yes | Identity type (e.g., `iam_role`, `service_account`) |
| `vendor` | string | Yes | Cloud vendor |
| `owner` | string | No | Owner of the identity |
| `purpose` | string | No | Purpose of the identity |
| `grants` | object | Yes | Grant properties |
| `grants.has_wildcard` | boolean | Yes | Whether identity has wildcard permissions |
| `scope` | object | Yes | Access scope |
| `scope.distinct_systems` | integer | Yes | Number of distinct systems accessed (min 0) |
| `scope.distinct_resource_groups` | integer | Yes | Number of distinct resource groups accessed (min 0) |
| `source` | [source_ref](#source-reference) | No | Source file reference |

## Source Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `file` | string | No | Source file path |
| `line` | integer | No | Line number in source file (min 1) |

## File Layout

Observations are stored as flat JSON files — one file per timestamp. Do **not** wrap multiple snapshots in a `"snapshots"` array; the schema rejects this.

```
observations/
├── 2026-01-01T00:00:00Z.json
├── 2026-01-02T00:00:00Z.json
└── 2026-01-03T00:00:00Z.json
```

File naming is not enforced by schema, but using the `captured_at` timestamp as the filename is the convention used in examples and tests.

## Validation

`stave validate` performs full [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12) validation using the [`santhosh-tekuri/jsonschema`](https://github.com/santhosh-tekuri/jsonschema) library. The schema is embedded in the binary — no external files or network access needed.

Validation also runs automatically at the start of `stave apply`, so inputs are always checked before evaluation begins.

### What the schema enforces

| Constraint | Detail |
|------------|--------|
| `additionalProperties: false` | Extra fields are rejected at every level. A `"snapshots"` wrapper array, for example, causes immediate failure. |
| Required fields | `schema_version`, `captured_at`, `assets` |
| `const` version | `schema_version` must be exactly `"obs.v0.1"` |
| Timestamp format | `captured_at` must be RFC 3339 (`date-time`) |
| Resource required fields | Each asset must have `id`, `type`, `vendor`, `properties` |
| String minimums | `id`, `type`, `vendor` must be non-empty (`minLength: 1`) |
| Identity required fields | `id`, `type`, `vendor`, `grants` (with `has_wildcard`), `scope` (with `distinct_systems`, `distinct_resource_groups`) |
| Integer minimums | `scope.distinct_systems` and `scope.distinct_resource_groups` must be >= 0; `source.line` must be >= 1 |

### Commands

```bash
# Validate a single observation file
stave validate --in observations/2026-01-01T00:00:00Z.json

# Validate all observations in a directory
stave validate --observations observations/

# Validate from stdin
cat snapshot.json | stave validate --in -

# JSON output for programmatic use
stave validate --observations observations/ --format json
```

Exit codes: 0 = valid, 2 = validation errors found.

## Schema Source

The canonical schema file is [`schemas/obs.v0.1.schema.json`](../../schemas/obs.v0.1.schema.json).

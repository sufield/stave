---
title: "Output Schema (out.v0.1)"
sidebar_label: "out.v0.1"
sidebar_position: 2
description: "Reference for Stave evaluation output contract out.v0.1."
---

# Output Schema — `out.v0.1`

This page documents the evaluation output contract used by Stave. Every `apply` and `apply --profile aws-s3` command produces JSON conforming to this structure.

The output contract is defined by Go struct types in `internal/domain/evaluation/` and `internal/adapters/output/dto/types.go`, with runtime validation against embedded JSON Schema (`schemas/output/v0.1/output.schema.json`) before emission. The schema version constant is `SchemaOutput` in `internal/domain/kernel/schema.go`.

## Top-Level Structure

```json
{
  "schema_version": "out.v0.1",
  "kind": "evaluation",
  "run": { ... },
  "summary": { ... },
  "findings": [ ... ],
  "skipped": [ ... ],
  "skipped_resources": [ ... ],
  "extensions": { ... }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | string | Yes | Always `"out.v0.1"` |
| `kind` | string | Yes | Always `"evaluation"` |
| `run` | [run](#run) | Yes | Run metadata |
| `summary` | [summary](#summary) | Yes | Aggregate counts |
| `findings` | array of [finding](#finding) | Yes | Detected violations (empty array when none) |
| `skipped` | array of [skipped_control](#skipped_control) | No | Controls that could not be evaluated |
| `skipped_resources` | array of [skipped_resource](#skipped_resource) | No | Assets exempted by ignore rules |
| `extensions` | object | No | Extension metadata (for example selected control source and resolved pack IDs) |

## `run`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tool_version` | string | Yes | Stave binary version |
| `offline` | boolean | Yes | Always `true` (Stave is architecturally offline) |
| `now` | string (RFC 3339) | Yes | Evaluation timestamp (from `--now` or derived from last snapshot) |
| `max_unsafe` | string | Yes | Maximum unsafe duration threshold (e.g., `"168h0m0s"`) |
| `snapshots` | integer | Yes | Number of observation snapshots loaded |
| `input_hashes` | [input_hashes](#input_hashes) | No | SHA-256 hashes of input files (for auditability) |

### `input_hashes`

| Field | Type | Description |
|-------|------|-------------|
| `files` | object | Maps each observation filename to its SHA-256 hex digest |
| `overall` | string | SHA-256 of the canonical `"filename=hash\n"` string (files sorted lexicographically) |

## `summary`

| Field | Type | Description |
|-------|------|-------------|
| `assets_evaluated` | integer | Number of assets evaluated |
| `attack_surface` | integer | Number of assets currently in an unsafe state |
| `violations` | integer | Number of findings (violations) |

## `finding`

Each finding represents a single control violation for a specific asset.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `control_id` | string | Yes | ID of the violated control (e.g., `"CTL.S3.PUBLIC.001"`) |
| `control_name` | string | Yes | Human-readable control name |
| `control_description` | string | Yes | What the control checks |
| `asset_id` | string | Yes | ID of the violating asset |
| `asset_type` | string | Yes | Asset type (e.g., `"storage_bucket"`) |
| `asset_vendor` | string | Yes | Cloud vendor (e.g., `"aws"`) |
| `source` | [source_ref](#source_ref) | No | Source file reference from the observation |
| `evidence` | [evidence](#evidence) | Yes | Proof of the violation |
| `control_severity` | string | No | Severity level of the violated control (`critical`, `high`, `medium`, `low`, `info`) |
| `control_compliance` | object | No | Compliance framework mappings from the control (framework name → control ID) |
| `remediation` | [remediation](#remediation) | Yes | Remediation guidance |
| `fix_plan` | [fix_plan](#fix_plan) | No | Machine-readable deterministic fix actions |

### `source_ref`

| Field | Type | Description |
|-------|------|-------------|
| `file` | string | Source file path |
| `line` | integer | Line number in source file |

### `evidence`

Fields are populated depending on the control type.

**Duration controls:**

| Field | Type | Description |
|-------|------|-------------|
| `first_unsafe_at` | string (RFC 3339) | When the asset first entered the unsafe state |
| `last_seen_unsafe_at` | string (RFC 3339) | When the asset was last observed unsafe |
| `unsafe_duration_hours` | number | Hours the asset has been continuously unsafe |
| `threshold_hours` | number | Maximum allowed unsafe duration (from `--max-unsafe` or per-control param) |

**Recurrence controls:**

| Field | Type | Description |
|-------|------|-------------|
| `episode_count` | integer | Number of unsafe episodes within the window |
| `window_days` | integer | Rolling window for counting recurrence |
| `recurrence_limit` | integer | Maximum allowed episodes before violation |
| `first_episode_at` | string (RFC 3339) | When the first unsafe episode started |
| `last_episode_at` | string (RFC 3339) | When the most recent unsafe episode ended |

**Common fields (all control types):**

| Field | Type | Description |
|-------|------|-------------|
| `misconfigurations` | array | Property-level unsafe conditions (`property`, `actual_value`, `operator`, `unsafe_value`) |
| `root_causes` | array of strings | Mechanisms causing the violation (e.g., `"policy"`, `"acl"`) |
| `source_evidence` | [source_evidence](#source_evidence) | Pointers to specific policy/ACL entries |
| `why_now` | string | Human-readable explanation of timing context |

### `source_evidence`

| Field | Type | Description |
|-------|------|-------------|
| `policy_public_statements` | array of strings | SIDs or indices of policy statements granting public access |
| `acl_public_grantees` | array of strings | Grantee URIs granting public access (e.g., `"AllUsers"`) |

### `remediation`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `description` | string | Yes | What the violation means |
| `action` | string | Yes | How to remediate |
| `example` | string | No | Example safe configuration |

### `fix_plan`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Stable fix-plan identifier |
| `target` | object | Yes | Asset target (`asset_id`, `asset_type`) |
| `preconditions` | array of strings | No | Conditions to verify before applying actions |
| `actions` | array | Yes | Deterministic action list |
| `actions[].action_type` | enum | Yes | `set`, `add`, `remove` |
| `actions[].path` | string | Yes | Canonical model path to change |
| `actions[].value` | any | No | Value to set/add |
| `expected_effect` | string | No | Expected security effect |

## `skipped_control`

| Field | Type | Description |
|-------|------|-------------|
| `control_id` | string | ID of the skipped control |
| `control_name` | string | Name of the skipped control |
| `reason` | string | Why the control was skipped |

## `skipped_resource`

| Field | Type | Description |
|-------|------|-------------|
| `asset_id` | string | ID of the skipped asset |
| `matched_pattern` | string | Ignore pattern that matched |
| `reason` | string | Exemption reason |

## `rows[]` (optional, `--explain-all`)

When `--explain-all` is enabled, each row represents one `(control, asset)` evaluation decision.

| Field | Type | Description |
|-------|------|-------------|
| `control_id` | string | Control ID |
| `asset_id` | string | Asset ID |
| `decision` | enum | `VIOLATION`, `PASS`, `INCONCLUSIVE`, `NOT_APPLICABLE`, `SKIPPED` |
| `confidence` | enum | `high`, `medium`, `low`, `inconclusive` |
| `evidence` | [evidence](#evidence) | Evidence (present for violations) |
| `why_now` | string | Timing explanation |
| `reason` | string | Reason for `SKIPPED` or `NOT_APPLICABLE` decisions |

## Minimal Example

```json
{
  "schema_version": "out.v0.1",
  "kind": "evaluation",
  "run": {
    "tool_version": "0.0.1",
    "offline": true,
    "now": "2026-01-11T00:00:00Z",
    "max_unsafe": "168h0m0s",
    "snapshots": 2
  },
  "summary": {
    "assets_evaluated": 1,
    "attack_surface": 0,
    "violations": 0
  },
  "findings": []
}
```

## Violation Example

```json
{
  "schema_version": "out.v0.1",
  "kind": "evaluation",
  "run": {
    "tool_version": "0.0.1",
    "offline": true,
    "now": "2026-01-11T00:00:00Z",
    "max_unsafe": "168h0m0s",
    "snapshots": 3,
    "input_hashes": {
      "files": {
        "2026-01-01T000000Z.json": "26770e3c...",
        "2026-01-10T000000Z.json": "cce8bb1c...",
        "2026-01-11T000000Z.json": "9218f381..."
      },
      "overall": "8761e974..."
    }
  },
  "summary": {
    "assets_evaluated": 2,
    "attack_surface": 1,
    "violations": 1
  },
  "findings": [
    {
      "control_id": "CTL.EXP.DURATION.001",
      "control_name": "Unsafe Exposure Duration Bound",
      "control_description": "An asset must not remain unsafe beyond the configured time window.",
      "asset_id": "res:aws:s3:bucket:public-bucket",
      "asset_type": "storage_bucket",
      "asset_vendor": "aws",
      "source": { "file": "infra/main.tf", "line": 42 },
      "evidence": {
        "first_unsafe_at": "2026-01-01T00:00:00Z",
        "last_seen_unsafe_at": "2026-01-11T00:00:00Z",
        "unsafe_duration_hours": 240,
        "threshold_hours": 168,
        "misconfigurations": [
          { "property": "public", "actual_value": true, "operator": "eq", "unsafe_value": true }
        ],
        "why_now": "Asset has been unsafe for 240 hours (threshold: 168 hours). Unsafe since 2026-01-01T00:00:00Z."
      },
      "control_severity": "critical",
      "control_compliance": {
        "cis_aws_v1.4.0": "2.1.5",
        "pci_dss_v3.2.1": "1.2.1",
        "soc2": "CC6.1"
      },
      "remediation": {
        "description": "Security control violation detected.",
        "action": "Review the finding evidence and remediate the configuration."
      }
    }
  ]
}
```

## Contract Sources

This reference is derived from the runtime output implementation:

- [`internal/adapters/output/dto/types.go`](../../internal/adapters/output/dto/types.go) — `ResultDTO`, output DTO structs
- [`internal/domain/kernel/schema.go`](../../internal/domain/kernel/schema.go) — `SchemaOutput` constant
- [`internal/domain/evaluation/result.go`](../../internal/domain/evaluation/result.go) — `SkippedControl`, `Summary`, `Decision`, `ConfidenceLevel`
- [`internal/domain/evaluation/run_info.go`](../../internal/domain/evaluation/run_info.go) — `RunInfo`, `InputHashes`
- [`internal/domain/evaluation/finding.go`](../../internal/domain/evaluation/finding.go) — `Finding`, `FindingDetail`
- [`internal/domain/evaluation/evidence.go`](../../internal/domain/evaluation/evidence.go) — `Evidence`, `SourceEvidence`
- [`internal/domain/policy/misconfiguration.go`](../../internal/domain/policy/misconfiguration.go) — `Misconfiguration`
- [`internal/domain/policy/exemption.go`](../../internal/domain/policy/exemption.go) — `SkippedResource`
- [`internal/adapters/output/dto/types.go`](../../internal/adapters/output/dto/types.go) — `SkippedAssetDTO`
- [`testdata/e2e/**/output.json`](../../testdata/e2e/) — Real output instances

---
title: "Diagnose Schema (diagnose.v1)"
sidebar_label: "diagnose.v1"
sidebar_position: 4
description: "Reference for Stave diagnose output contract diagnose.v1."
---

# Diagnose Schema — `diagnose.v1`

This page documents the JSON output contract for `stave diagnose --format json`.

The contract is validated at runtime against the embedded schema:

- `schemas/diagnose/v1/diagnose.schema.json`

## Top-Level Structure

```json
{
  "schema_version": "diagnose.v1",
  "report": {
    "diagnostics": [ ... ],
    "summary": { ... }
  }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `schema_version` | string | Yes | Always `"diagnose.v1"` |
| `report` | object | Yes | Diagnose report payload |

## `report.diagnostics[]`

Each diagnostic explains one likely cause for unexpected evaluation outcomes.

| Field | Type | Required | Description |
|---|---|---|---|
| `case` | string | Yes | Diagnostic category |
| `signal` | string | Yes | Short diagnosis signal |
| `evidence` | string | Yes | Supporting evidence text |
| `action` | string | Yes | Suggested corrective action |
| `command` | string | No | Optional command hint |

## `report.summary`

| Field | Type | Required | Description |
|---|---|---|---|
| `total_snapshots` | integer | Yes | Number of loaded snapshots |
| `total_resources` | integer | Yes | Number of resources observed |
| `total_controls` | integer | Yes | Number of controls loaded |
| `time_span` | integer | Yes | Observation span (nanoseconds duration) |
| `min_captured_at` | string (RFC3339) | Yes | Earliest snapshot time |
| `max_captured_at` | string (RFC3339) | Yes | Latest snapshot time |
| `evaluation_time` | string (RFC3339) | Yes | Effective evaluation time (`--now` or runtime clock) |
| `max_unsafe_threshold` | integer | Yes | Max unsafe threshold (nanoseconds duration) |
| `violations_found` | integer | Yes | Violations count in evaluated result |
| `attack_surface` | integer | Yes | Attack surface resources count |

## Minimal Example

```json
{
  "schema_version": "diagnose.v1",
  "report": {
    "diagnostics": [],
    "summary": {
      "total_snapshots": 2,
      "total_resources": 5,
      "total_controls": 12,
      "time_span": 86400000000000,
      "min_captured_at": "2026-01-10T00:00:00Z",
      "max_captured_at": "2026-01-11T00:00:00Z",
      "evaluation_time": "2026-01-11T00:00:00Z",
      "max_unsafe_threshold": 604800000000000,
      "violations_found": 0,
      "attack_surface": 0
    }
  }
}
```

---
title: "Bug Reproduction Guide"
sidebar_label: "Bug Repro Guide"
sidebar_position: 1
description: "How to write a minimal, deterministic bug reproduction for Stave."
---

# Bug Reproduction Guide

A good bug report includes a minimal reproduction that any contributor can run. This guide explains how to write one.

## Principles

1. **Deterministic** — use `--now` to fix the evaluation timestamp. Never rely on wall-clock time.
2. **Minimal** — include only the fields and assets needed to trigger the bug. Remove everything else.
3. **Sanitized** — replace real bucket names, ARNs, account IDs, and tags with placeholders. Use `--sanitize` or manually substitute.
4. **Self-contained** — the reproduction should run with only the Stave binary and the files you provide. No cloud credentials, no external dependencies.
5. **No network** — Stave is offline. Your repro should work in an air-gapped environment.

## Quick Template

Use the [bug reproduction template](./bug-repro-template.md) as a starting point. It provides:

- A minimal sanitized observation file
- A Go test harness that asserts exit code and JSON output
- Version printing for debugging
- Automatic cleanup

## Step-by-Step

### 1. Identify the minimum input

Start with your full observation file and strip fields until the bug disappears. Then add back the last field you removed — that's your minimal reproduction.

### 2. Sanitize sensitive data

Replace real values with placeholders:

| Real value | Replacement |
|-----------|-------------|
| Bucket names | `SANITIZED_01`, `test-bucket` |
| Account IDs | `123456789012` |
| ARNs | `arn:aws:s3:::SANITIZED_01` |
| Tags | Remove or use generic values |
| Policies | Simplify to minimum triggering structure |

Or use Stave's built-in sanitization:

```bash
stave apply --controls ./controls --observations ./obs --sanitize > sanitized-output.json
stave ingest --profile mvp1-s3 --input ./snapshot --out obs.json --scrub
```

### 3. Write the observation file

Create a minimal `obs.v0.1` observation:

```json
{
  "schema_version": "obs.v0.1",
  "captured_at": "2026-01-01T00:00:00Z",
  "assets": [{
    "id": "res:aws:s3:bucket:SANITIZED_01",
    "type": "storage_bucket",
    "vendor": "aws",
    "properties": {
      "storage": {
        "visibility": { "public_read": true }
      }
    }
  }]
}
```

For duration bugs, include at least two snapshots with different timestamps.

### 4. Write the reproduction command

```bash
STAVE_BIN="${STAVE_BIN:-stave}"
NOW="2026-01-01T00:00:00Z"

$STAVE_BIN apply \
  --controls controls/s3 \
  --observations ./repro-observations/ \
  --now "$NOW" \
  --allow-unknown-input

echo "Exit code: $?"
```

Use `|| rc=$?` instead of `set -e` when expecting non-zero exit codes:

```bash
rc=0
$STAVE_BIN apply --controls ./controls --observations ./obs --now "$NOW" || rc=$?
echo "Exit code: $rc"
```

### 5. Document expectations

In your bug report, state clearly:

- **Expected behavior** — what should happen (exit code, output structure, finding count)
- **Actual behavior** — what actually happens
- **Stave version** — output of `stave --version`
- **OS and architecture** — `uname -a` or equivalent

## What to Include in the Issue

```markdown
## Bug Report

**Stave version:** v1.2.3
**OS:** Linux x86_64 / macOS arm64

### Steps to reproduce

1. Save the attached observation file as `obs/snapshot.json`
2. Run: `stave apply --controls controls/s3 --observations obs/ --now 2026-01-01T00:00:00Z`
3. Observe exit code X

### Expected
Exit code 3 with finding for CTL.S3.PUBLIC.001

### Actual
Exit code 0 with no findings

### Minimal observation
(attach sanitized JSON)
```

## Common Pitfalls

| Pitfall | Fix |
|---------|-----|
| Non-deterministic output | Always use `--now` |
| `set -e` with expected non-zero exit | Use `\|\| rc=$?` pattern |
| Missing second snapshot for duration bugs | Include 2+ snapshot files |
| Real infrastructure data in report | Sanitize all identifiers |
| Missing `--allow-unknown-input` for custom source types | Add the flag or omit `generated_by` |

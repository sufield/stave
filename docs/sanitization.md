---
title: "Sanitization and Scrubbing"
sidebar_label: "Sanitization"
sidebar_position: 7
description: "How to share Stave outputs safely using --sanitize and ingest --profile aws-s3 --scrub."
---

# Sanitization and Scrubbing

Stave provides two complementary privacy controls for safe sharing.

## `--sanitize` (Output Sanitization)

`--sanitize` sanitizes infrastructure identifiers in command output.

Use it on commands that emit findings, diagnostics, or coverage graphs:

```bash
stave apply --controls ./controls --observations ./obs --sanitize
stave apply --controls ./controls --observations ./obs --sanitize --now 2026-01-15T00:00:00Z
stave diagnose --controls ./controls --observations ./obs --sanitize
stave graph coverage --controls ./controls --observations ./obs --sanitize
```

What stays visible:

- control IDs and names
- counts, durations, timestamps
- schema versions and summary totals

## `ingest --profile aws-s3 --scrub` (Input Scrubbing)

`ingest --profile aws-s3 --scrub` removes or sanitizes sensitive fields in extracted observations before sharing.

```bash
stave ingest --profile aws-s3 --input ./aws-snapshot --out observations.scrubbed.json --scrub
```

Use this when you need to share observation files themselves.

## Recommended Sharing Workflow

1. Create scrubbed observations:
   `stave ingest --profile aws-s3 --input ./aws-snapshot --out observations.scrubbed.json --scrub`
2. Evaluate with sanitization:
   `stave apply --profile aws-s3 --input observations.scrubbed.json --sanitize > evaluation.sanitized.json`
3. Share only scrubbed observations and sanitized output.

## Path Rendering

Use `--path-mode` to control path visibility in errors/logs:

- `--path-mode=base` (default): basename only
- `--path-mode=full`: full absolute paths

For shared artifacts, prefer `--path-mode=base`.

## Related Docs

- [Security Policy](../SECURITY.md)
- [Offline & Air-Gapped Operation](offline-airgapped.md)

---
title: "Sanitization"
sidebar_label: "Sanitization"
sidebar_position: 7
description: "How to share Stave outputs safely using --sanitize."
---

# Sanitization

Stave provides output sanitization for safe sharing.

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

## Input Scrubbing

To sanitize observation files before sharing, handle scrubbing in your extractor. Your extractor (any language producing `obs.v0.1` JSON) should strip or replace sensitive identifiers before writing output. See [Building an Extractor](extractor-prompt.md) for guidance.

## Recommended Sharing Workflow

1. Produce sanitized observations using your extractor (strip real bucket names, account IDs, ARNs).
2. Evaluate with sanitization:
   `stave apply --controls ./controls --observations ./observations --sanitize > evaluation.sanitized.json`
3. Share only sanitized observations and sanitized output.

## Path Rendering

Use `--path-mode` to control path visibility in errors/logs:

- `--path-mode=base` (default): basename only
- `--path-mode=full`: full absolute paths

For shared artifacts, prefer `--path-mode=base`.

## Related Docs

- [Security Policy](../SECURITY.md)
- [Offline & Air-Gapped Operation](offline-airgapped.md)

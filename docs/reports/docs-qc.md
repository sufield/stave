---
title: "Documentation QC Report"
sidebar_label: "Docs QC"
sidebar_position: 1
description: "Post-fix documentation integrity report for Stave."
---

# Documentation QC Report

Generated: 2026-02-20

## Scope

This report verifies the documentation gaps previously identified in `open-source-prompt.md` follow-up checks.

## Gap Status

All previously identified missing docs pages are now present:

| Item | Status | Path |
|------|--------|------|
| Evaluation semantics page | Fixed | `docs/evaluation-semantics.md` |
| Offline/air-gapped page | Fixed | `docs/offline-airgapped.md` |
| Sanitization page | Fixed | `docs/sanitization.md` |
| Control migration guide | Fixed | `controls/MIGRATION.md` |
| Output schema reference page | Fixed | `docs/schema/out.v0.1.md` |

## Link Integrity (Targeted)

Targeted link checks now resolve correctly:

- `README.md` links:
  - `docs/evaluation-semantics.md`
  - `docs/offline-airgapped.md`
  - `docs/sanitization.md`
  - `controls/MIGRATION.md`
- `SECURITY.md` links:
  - `docs/offline-airgapped.md`
  - `docs/sanitization.md`
- `docs/project/stability.md` link:
  - `../../controls/MIGRATION.md`

No broken links remain for these previously failing paths.

## Stale Command References

`SECURITY.md` no longer uses removed command `stave report` in examples.

## Schema Reference Coverage

Schema reference docs now include:

- `docs/schema/obs.v0.1.md`
- `docs/schema/out.v0.1.md`
- `docs/schema/ctrl.v1.md`

`docs/start-here.md` includes links to all three.

## Notes

`out.v0.1` is currently documented from runtime output contract sources and e2e output instances:

- `internal/domain/evaluation_result.go` and related domain types
- `testdata/e2e/**/output.json`


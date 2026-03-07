---
title: "Offline & Air-Gapped Operation"
sidebar_label: "Offline & Air-Gapped"
sidebar_position: 6
description: "What runs offline in Stave, what still needs network access, and recommended deployment patterns."
---

# Offline & Air-Gapped Operation

Stave runtime commands are designed for offline execution against local files.

## Runtime Behavior (Offline)

The runtime CLI (`stave`) operates on local inputs and does not require cloud credentials or network access.

Typical offline flow:

1. Prepare local observation and control files.
2. Run `stave validate`, `stave apply`, `stave apply --profile aws-s3`, or `stave diagnose`.
3. Consume local JSON/text output.

## What Is In Scope for Air-Gapped Use

- Running the released `stave` binary
- Validating observations/controls
- Evaluating findings from local snapshots
- Diagnosing previous output with local inputs

## What Is Not Offline

These activities are outside runtime execution and may require network:

- downloading dependencies while building from source
- CI workflows
- release signing and attestation publication
- uploading release artifacts

## Operational Guidance

- Treat observation and output files as sensitive.
- Use `--sanitize` for shared outputs.
- Use `ingest --profile aws-s3 --scrub` before sharing extracted observations.
- Prefer deterministic runs in CI with `--now`.

## Related Docs

- [Execution Safety](trust/execution-safety.md)
- [Data Flow and I/O](trust/data-flow-and-io.md)
- [Release Security](trust/02-release-security.md)
- [Sanitization and Scrubbing](sanitization.md)

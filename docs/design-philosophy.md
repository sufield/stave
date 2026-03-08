# Design Philosophy

Stave is designed around open standards from the first release so teams can adopt it without platform lock-in.

## Core Principles

1. Contract-first: data is exchanged through versioned, documented schemas.
2. Vendor-neutral: extractors can be built in any language and for any platform.
3. Deterministic by default: same inputs + same `--now` produce the same output.
4. Offline-capable: evaluation and validation work without cloud credentials.
5. Composable CLI: commands fit CI/CD pipelines through stable flags, outputs, and exit codes.

## Standardization Surface

- Controls: `ctrl.v1` YAML
- Observations: `obs.v0.1` JSON
- Evaluation/verification output: `out.v0.1` JSON
- JSON Schema contracts under `schemas/`

Because these are open files and versioned contracts, teams can:

- Generate observations from their own systems and tools
- Validate data independently in other runtimes
- Store, diff, and audit artifacts in any repository or data platform
- Change cloud vendors or scanners without rewriting Stave core logic

## What This Means in Practice

- Stave does not require a proprietary agent or hosted control plane.
- Stave does not require a vendor-specific policy language to start.
- Stave artifacts remain portable across local development, CI runners, and audit workflows.

This is intentional: Stave should be a standards-based safety layer, not a closed ecosystem.

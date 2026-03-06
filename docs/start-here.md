---
title: "Start Here"
sidebar_label: "Start Here"
sidebar_position: 0
description: "Reading order index for Stave documentation."
---

# Start Here

This page provides a recommended reading order for understanding Stave. Start with the sections that match your role.

## For Everyone

| Order | Document | What You'll Learn |
|-------|----------|-------------------|
| 1 | [README](../README.md) | What Stave does, quickstart, CLI commands |
| 2 | [Security Guarantees](trust/01-guarantees.md) | Every guarantee: offline, no-creds, determinism, no-exec, filesystem safety |
| 3 | [Scope and Limits](project/limits.md) | What Stave does and does not do |

## For Security Reviewers

| Order | Document | What You'll Learn |
|-------|----------|-------------------|
| 4 | [Threat Model](security/threat-model.md) | Assets, trust boundaries, attacker profiles, controls, residual risks |
| 5 | [Execution Safety](trust/execution-safety.md) | No-exec guarantees: banned imports, closed DSL, no plugins |
| 6 | [Data Flow and I/O](trust/data-flow-and-io.md) | Per-command I/O model, permission policy, overwrite protection |
| 7 | [Release Security](trust/02-release-security.md) | How releases are built, signed, and verified |
| 8 | [Verify a Release](trust/verify-release.md) | Step-by-step verification commands |

## For Developers

| Order | Document | What You'll Learn |
|-------|----------|-------------------|
| 9 | [Architecture Overview](architecture/overview.md) | Pipeline, package map, trust boundaries, command routing |
| 10 | [Stability and Versioning](project/stability.md) | Schema stability, exit codes, dependency pinning |
| 11 | [Docs-As-Code](project/docs-as-code.md) | Docs source of truth, generation, CI validation, publishing workflow |
| 12 | [Observation Schema](schema/obs.v0.1.md) | obs.v0.1 field reference |
| 13 | [Output Schema](schema/out.v0.1.md) | out.v0.1 evaluation output contract |
| 14 | [Control Schema](schema/ctrl.v1.md) | ctrl.v1 field reference, operator table |
| 15 | [Authoring Controls](controls/authoring.md) | How to write, test, and review custom controls |
| 16 | [CONTRIBUTING.md](../CONTRIBUTING.md) | Dev setup, testing, PR process |

## For Bug Reporters

| Order | Document | What You'll Learn |
|-------|----------|-------------------|
| 17 | [Bug Reproduction Guide](contrib/bug-repro-guide.md) | How to write a minimal, deterministic repro |
| 18 | [Bug Reproduction Template](contrib/bug-repro-template.md) | Copy-paste template for reproductions |

## Examples

Self-contained scenarios you can run immediately after building Stave:

| Example | What It Shows |
|---------|--------------|
| [`examples/public-bucket/`](../examples/public-bucket/) | Detect a publicly readable S3 bucket |
| [`examples/missing-pab/`](../examples/missing-pab/) | Detect missing Public Access Block |
| [`examples/duration/`](../examples/duration/) | Duration-based violation (unsafe too long) |

## Existing Reference Docs

| Document | Covers |
|----------|--------|
| [Security and Trust](trust/01-security-and-trust.md) | Trust document index |
| [Scope and Support](scope-and-support.md) | Supported commands and surfaces |
| [Evaluation Engine Capabilities](evaluation-engine-capabilities.md) | Operator and type coverage map |
| [SECURITY.md](../SECURITY.md) | Vulnerability reporting policy |

## Docs Feedback

If a task intent is missing (for example, an "I want to ..." item), submit a docs suggestion:

`https://github.com/sufield/stave/issues/new?template=docs_feedback.yml&title=docs%3A%20missing%20intent%20-%20`

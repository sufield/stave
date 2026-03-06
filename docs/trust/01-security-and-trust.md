---
title: "Security and Trust"
sidebar_label: "Security and Trust"
sidebar_position: 2
description: "Overview of Stave's security design and trust model."
---

# Security and Trust

Stave is designed with a minimal attack surface and a verifiable release pipeline.

## Security Design

- **No network access** -- Stave makes zero network connections at runtime. It reads local files and writes to stdout/stderr.
- **No subprocess execution** -- Stave does not shell out to external tools.
- **No persistent state** -- No databases, caches, or config files are created.
- **Read-only inputs** -- Observation and control files are never modified.
- **Air-gapped compatible** -- The binary contains no networking code. See [Offline & Air-Gapped Operation](../offline-airgapped.md).

## Trust Documents

| Document | Covers |
|----------|--------|
| [Security Guarantees](./01-guarantees.md) | Full inventory of every guarantee: offline, no-creds, determinism, no-exec, filesystem safety, sanitization, supply chain |
| [Release Security](./02-release-security.md) | How releases are built, signed, and verified (checksums, Cosign, SBOM, provenance) |
| [Offline & Air-Gapped Operation](../offline-airgapped.md) | Network dependency inventory for build vs runtime |
| [Execution Safety](./execution-safety.md) | No-exec guarantees: no plugins, no templates, no interpreters, closed DSL |
| [Sharing Outputs Safely](../sanitization.md) | Sanitization and scrubbing for safe output sharing |
| [Data Flow and I/O](./data-flow-and-io.md) | Per-command I/O model, permission policy, overwrite protection, stdin convention |
| [Evaluation Engine Capabilities](../evaluation-engine-capabilities.md) | What the engine supports vs. what S3 controls use — MVP 1.0+ candidate code |

## Vulnerability Reporting

Report security vulnerabilities through [GitHub Security Advisories](https://github.com/sufield/stave/security/advisories/new). See [SECURITY.md](../../SECURITY.md) for the full policy.

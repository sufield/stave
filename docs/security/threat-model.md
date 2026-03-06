---
title: "Threat Model"
sidebar_label: "Threat Model"
sidebar_position: 1
description: "Stave's threat model: assets, trust boundaries, attacker profiles, controls, and residual risks."
---

# Threat Model

This document describes the assets Stave protects, the threats it faces, and how each is mitigated.

## Assets

| Asset | Sensitivity | Where |
|-------|-------------|-------|
| Observation snapshots | May contain infrastructure details, bucket names, ARNs, tags | User filesystem (input) |
| Evaluation findings | Reveals which resources are unsafe and why | stdout or `--out` file |
| Stave binary | Must be authentic and untampered | User filesystem / release download |
| Control definitions | Define what "unsafe" means; tampering changes evaluation semantics | User filesystem or shipped pack |

## Trust Boundaries

### 1. File Input Boundary

Stave reads observation and control files from the local filesystem. Observations are treated as **untrusted input** — they may come from external tools and could be malformed or crafted.

**Controls:**
- Full JSON Schema validation with `additionalProperties: false` — extra fields cause immediate rejection.
- Path traversal protection on control registry paths.
- Bucket name validation against S3 naming rules before use in file paths.
- All user-supplied paths cleaned with `filepath.Clean`.

### 2. File Output Boundary

Stave writes findings to stdout or to files specified by `--out`.

**Controls:**
- No-overwrite by default — refuses to write over existing files without `--force`.
- No-symlink-write by default — refuses to write through symbolic links without `--allow-symlink-output`.
- Restricted permissions: directories `0700`, files `0600`.
- No implicit temp files, caches, or config directories.

### 3. Build and Release Boundary

The release pipeline builds, signs, and publishes artifacts.

**Controls:**
- SHA-256 checksums for integrity.
- Sigstore Cosign keyless signing via GitHub Actions OIDC.
- SPDX SBOM for dependency transparency.
- GitHub-native SLSA build provenance attestation.
- License compliance (`go-licenses check`) — GPL/AGPL/SSPL/LGPL fail the build.
- Dependabot for dependency monitoring.
- govulncheck on every PR.

## Attacker Profiles

### A1: Malicious Input

**Goal:** Exploit Stave through crafted observation or control files.

| Attack Vector | Control |
|---------------|---------|
| Schema injection (extra fields) | `additionalProperties: false` rejects unknown fields |
| Path traversal via resource IDs | Bucket name validation; `filepath.Clean` on all paths |
| Path traversal via control registry | Registry validates relative paths stay within root |
| Oversized input (DoS) | Go's JSON/YAML parsers have bounded memory; no unbounded buffering |
| Malformed timestamps | RFC 3339 parsing rejects invalid dates |

### A2: Supply-Chain Attack

**Goal:** Replace the Stave binary or its dependencies with a malicious version.

| Attack Vector | Control |
|---------------|---------|
| Artifact tampering in transit | SHA-256 checksums detect modification |
| Malicious release replacement | Cosign signature binds artifacts to CI workflow identity |
| Compromised build host | GitHub provenance attestation proves CI origin |
| Hidden dependencies | SBOM provides full dependency audit trail |
| Vulnerable dependencies | govulncheck on every PR; Dependabot monitoring |
| Unauthorized release | Sigstore OIDC ties signing to GitHub Actions context |

### A3: Local Attacker

**Goal:** Read evaluation results or tamper with output on a shared system.

| Attack Vector | Control |
|---------------|---------|
| Read output files | `0600` file permissions (owner-only) |
| Read output directories | `0700` directory permissions |
| Symlink attack on output path | Symlink write protection (default on) |
| Overwrite existing files | No-overwrite protection (default on) |

### A4: Credential Harvesting

**Goal:** Use Stave as a vector to exfiltrate credentials.

| Attack Vector | Control |
|---------------|---------|
| Read credential env vars | Stave reads no credential env vars (only `NO_COLOR`) |
| Read credential files | Stave reads no credential files |
| Network exfiltration | No `net/http`, `net/rpc`, `crypto/tls` — architecturally impossible |
| Subprocess exfiltration | No `os/exec` — architecturally impossible |

## Residual Risks

These risks are acknowledged but not fully mitigated by Stave:

| Risk | Impact | Remediation Guidance |
|------|--------|-------------------|
| **Snapshot sensitivity** | Terraform exports may contain embedded secrets | Use `--sanitize` and `ingest --profile mvp1-s3 --scrub` when sharing output. Do not include raw secrets in state files passed to Stave. |
| **Umask on shared systems** | Weak umask may expose output files | Set `umask 077` before running Stave. Write to a private directory. |
| **Provenance requires network** | `gh attestation verify` needs GitHub API access | Checksum + Cosign verification are sufficient for offline environments. Provenance adds defense-in-depth when connectivity is available. |
| **Control tampering** | Modified controls change evaluation semantics | Ship controls from a trusted source. Validate with `stave validate` before evaluation. Use version control. |
| **Log verbosity** | `-vv` may include file paths in logs | Use `--path-mode=base` (default) to show basenames only. Defensive log sanitization strips known sensitive patterns. |

## Security Tests

The following CI tests enforce the threat model:

| Test | What It Enforces |
|------|-----------------|
| `TestNoBannedImportsInRuntime` | 8 banned packages not in runtime binary |
| `TestNoHTTPSchemaIdentifiers` | Schema IDs use `urn:` not `http:` |
| `TestNoCredentialEnvVars` | No credential environment variable reads |
| `TestOfflineHelpSuffix` | Help text documents offline operation |

## Further Reading

- [Security Guarantees](../trust/01-guarantees.md) — full guarantee inventory
- [Execution Safety](../trust/execution-safety.md) — no-exec guarantees
- [Release Security](../trust/02-release-security.md) — release verification
- [Data Flow and I/O](../trust/data-flow-and-io.md) — per-command I/O model
